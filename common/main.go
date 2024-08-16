package common

import (
	"errors"
)

type Result[T any] struct {
	Data T
	Err  error
}

func Ok[T any](value T) Result[T] {
	return Result[T]{ Data: value, Err: nil }
}

func Err[T any](err_str string) Result[T] {
	var zero T
	return Result[T]{ Data: zero, Err: errors.New(err_str) }
}
