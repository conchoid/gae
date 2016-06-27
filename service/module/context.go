// Copyright 2016 The LUCI Authors. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package module

import (
	"golang.org/x/net/context"
)

type key int

var (
	moduleKey       key
	moduleFilterKey key = 1
)

// Factory is the function signature for factory methods compatible with
// SetFactory.
type Factory func(context.Context) Interface

// Filter is the function signature for a filter module implementation. It gets
// the current module implementation, and returns a new module implementation
// backed by the one passed in.
type Filter func(context.Context, Interface) Interface

// getUnfiltered gets gets the Interface implementation from context without
// any of the filters applied.
func getUnfiltered(c context.Context) Interface {
	if f, ok := c.Value(moduleKey).(Factory); ok && f != nil {
		return f(c)
	}
	return nil
}

// Get gets the Interface implementation from context.
func Get(c context.Context) Interface {
	ret := getUnfiltered(c)
	if ret == nil {
		return nil
	}
	for _, f := range getCurFilters(c) {
		ret = f(c, ret)
	}
	return ret
}

// SetFactory sets the function to produce Interface instances, as returned
// by the Get method.
func SetFactory(c context.Context, gif Factory) context.Context {
	return context.WithValue(c, moduleKey, gif)
}

// Set sets the current Interface object in the context. Useful for testing
// with a quick mock. This is just a shorthand SetFactory invocation to set
// a factory which always returns the same object.
func Set(c context.Context, gi Interface) context.Context {
	return SetFactory(c, func(context.Context) Interface { return gi })
}

func getCurFilters(c context.Context) []Filter {
	curFiltsI := c.Value(moduleFilterKey)
	if curFiltsI != nil {
		return curFiltsI.([]Filter)
	}
	return nil
}

// AddFilters adds Interface filters to the context.
func AddFilters(c context.Context, filts ...Filter) context.Context {
	if len(filts) == 0 {
		return c
	}
	cur := getCurFilters(c)
	newFilts := make([]Filter, 0, len(cur)+len(filts))
	newFilts = append(newFilts, getCurFilters(c)...)
	newFilts = append(newFilts, filts...)
	return context.WithValue(c, moduleFilterKey, newFilts)
}