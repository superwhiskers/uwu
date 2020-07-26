/*

uwu - replacement for the go `plugin` package
copyright (C) 2018-2019 superwhiskers <whiskerdev@protonmail.com>

this source code form is subject to the terms of the mozilla public
license, v. 2.0. if a copy of the mpl was not distributed with this
file, you can obtain one at http://mozilla.org/MPL/2.0/.

*/

// +build linux,cgo darwin,cgo freebsd,cgo

package uwu

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"unsafe"
)

/*
#cgo linux LDFLAGS: -ldl

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

typedef char *(*init_or_destructor_function) ();

static char *call_init_or_destructor_function(init_or_destructor_function f) {
	return f();
}

typedef void *(*call_function) (char *, void **, int);

static void *call_call_function(call_function f, char *c, void **v, int i) {
	return f(c, v, i);
}

static uintptr_t open_plugin(const char *path, char **err) {
	void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (handle == NULL) {
		*err = (char *)(dlerror());
	}
	return (uintptr_t)(handle);
}

static void *lookup_symbol(uintptr_t handle, const char *name, char **err) {
	void *function = dlsym((void *)(handle), name);
	if (function == NULL) {
		*err = (char *)(dlerror());
	}
	return function;
}

static int close_plugin(uintptr_t handle, char **err) {
	if (dlclose((void *)(handle)) != 0) {
		*err = (char *)(dlerror());
		return 1;
	}
	return 0;
}
*/
import "C"

// Plugin represents a created plugin. all memory allocated by said plugin
// is assumed to be allocated on the c heap, and will be deallocated in
// that manner when it is finished
type Plugin struct {
	handle C.uintptr_t
	path   string

	// an init() function should take no arguments
	// and return a string. if the string is empty,
	// initialization is considered successful. if
	// not, an error is returned from the caller
	//
	// initialization functions should handle
	// multiple calls and be ready to be called
	// even when the plugin is already initialized.
	init C.init_or_destructor_function

	// a call() function should take three arguments
	// 1. the name of the function to call
	// 2. the arguments to the function (C.void-s)
	// 3. the argument count
	//
	// it should return an array of three void types,
	// which are an array of `C.void`s, the
	// number of `C.void`s, and a possible
	// `error`
	call C.call_function

	// a destroy() function should take no arguments
	// and return a string. if the string is empty,
	// destruction is considered successful. if not,
	// an error is returned from the caller.
	//
	// destructor functions, like initialization
	// functions, should handle multiple calls and
	// be ready to be called when the plugin is
	// already destroyed.
	destroy C.init_or_destructor_function

	calls int64
}

var (
	initFuncName    = []byte("init")
	callFuncName    = []byte("call")
	destroyFuncName = []byte("destroy")

	emptyString = []byte("")
)

// LoadPlugin creates a fresh Plugin from the filesystem
func LoadPlugin(path string) (p *Plugin, err error) {
	p = &Plugin{}
	p.path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	err = p.Load()

	return
}

// Load loads the plugin from the filesystem. if any of the function lookups fail, the plugin is unloaded from memory
func (p *Plugin) Load() (err error) {
	for !atomic.CompareAndSwapInt64(&p.calls, 0, -1) {
		continue
	}
	defer atomic.StoreInt64(&p.calls, 0)

	var cErr *C.char

	pointerPath := []byte(p.path)
	p.handle = C.open_plugin((*C.char)(unsafe.Pointer(&pointerPath)), &cErr)
	if p.handle == 0 {
		err = errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
		C.free(unsafe.Pointer(cErr))
		return
	}

	defer func() {
		if err != nil {
			nErr := p.Unload()
			if nErr != nil {
				err = errors.New(strings.Join([]string{"multiple errors encountered: (", nErr.Error(), ") (", err.Error(), ")"}, ""))
			}
		}
	}()

	t := (uintptr)(C.lookup_symbol(p.handle, (*C.char)(unsafe.Pointer(&initFuncName)), &cErr))
	if t == 0 {
		err = errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
		C.free(unsafe.Pointer(cErr))
		return
	} else {
		p.init = (C.init_or_destructor_function)(unsafe.Pointer(t))
	}
	t = (uintptr)(C.lookup_symbol(p.handle, (*C.char)(unsafe.Pointer(&callFuncName)), &cErr))
	if t == 0 {
		err = errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
		C.free(unsafe.Pointer(cErr))
		return
	} else {
		p.call = (C.call_function)(unsafe.Pointer(t))
	}
	t = (uintptr)(C.lookup_symbol(p.handle, (*C.char)(unsafe.Pointer(&destroyFuncName)), &cErr))
	if t == 0 {
		err = errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
		C.free(unsafe.Pointer(cErr))
		return
	} else {
		p.destroy = (C.init_or_destructor_function)(unsafe.Pointer(t))
	}

	// doesn't matter if it returns an error because this is the last statement anyways
	err = p.Init()
	return
}

// Unload unloads the plugin. if an error is returned the shared library is still unloaded from memory
func (p *Plugin) Unload() (err error) {
	for !atomic.CompareAndSwapInt64(&p.calls, 0, -1) {
		continue
	}

	var cErr *C.char

	defer func() {
		if C.close_plugin(p.handle, &cErr) != 0 {
			nErr := errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
			C.free(unsafe.Pointer(cErr))
			if err != nil {
				err = errors.New(strings.Join([]string{"multiple errors encountered: (", nErr.Error(), ") (", err.Error(), ")"}, ""))
			}
		}

		atomic.StoreInt64(&p.calls, 0)
	}()

	err = p.Destroy()
	return
}

// Init initializes the plugin
func (p *Plugin) Init() (err error) {
	for !atomic.CompareAndSwapInt64(&p.calls, 0, -1) {
		continue
	}
	defer atomic.StoreInt64(&p.calls, 0)

	cErr := C.call_init_or_destructor_function(p.init)
	if int(C.strcmp(cErr, (*C.char)(unsafe.Pointer(&emptyString)))) == 0 {
		err = errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
		C.free(unsafe.Pointer(cErr))
	}
	return
}

// Destroy deinitializes the plugin
func (p *Plugin) Destroy() (err error) {
	for !atomic.CompareAndSwapInt64(&p.calls, 0, -1) {
		continue
	}
	defer atomic.StoreInt64(&p.calls, 0)

	cErr := C.call_init_or_destructor_function(p.destroy)
	if int(C.strcmp(cErr, (*C.char)(unsafe.Pointer(&emptyString)))) == 0 {
		err = errors.New(strings.Join([]string{"error: ", C.GoString(cErr)}, ""))
		C.free(unsafe.Pointer(cErr))
	}
	return
}

// Reload reloads the plugin from the filesystem
func (p *Plugin) Reload() (err error) {
	err = p.Unload()
	if err != nil {
		return
	}

	err = p.Load()
	return
}

// Reinit destroys then reinitializes the plugin using the already loaded code
func (p *Plugin) Reinit() (err error) {
	err = p.Destroy()
	if err != nil {
		return
	}

	err = p.Init()
	return
}

// Call calls a function from the plugin using the provided function name and arguments
//
// Call will deallocate the memory it allocates for arguments, so any data that is to
// be retained must be saved on the side of the called function
//
// constraints:
//   - the called function *must* not return anything aside from an error if an error
//     has occurred as it will not be freed
//   - the callee must free all memory that it has provided as arguments if they are
//     heap-allocated
func (p *Plugin) Call(name string, args ...*C.void) (ret *C.void, err error) {

	/* ensure that we aren't initializing/deinitializing during execution */

	for i := atomic.LoadInt64(&p.calls); i == -1; {
		continue
	}
	atomic.AddInt64(&p.calls, 1)
	defer atomic.AddInt64(&p.calls, -1)

	/* give the called function an array of arguments */

	voidPtr := C.malloc((C.ulong)(C.sizeof_uintptr_t * C.int(len(args))))
	defer C.free(voidPtr)

	u := uintptr(voidPtr)
	for i := u; int(i-u) < len(args); i++ {
		*(**C.void)(unsafe.Pointer(i)) = args[i-u]
	}

	/* call the function */

	t := C.call_call_function(p.call, C.CString(name), &voidPtr, (C.int)(len(args)))

	r := *(*[2]*C.void)(unsafe.Pointer(&t))
	defer func() {
		C.free(unsafe.Pointer(r[1]))
		C.free(unsafe.Pointer(*(***C.void)(unsafe.Pointer(&r))))
	}()

	sErr := C.GoString((*C.char)(unsafe.Pointer(r[1])))
	if sErr != "" {
		err = errors.New(strings.Join([]string{"error: ", sErr}, ""))
		return
	}
	ret = r[0]

	return
}
