// This package re-implements [github.com/nfnt/resize.Resize] using [github.com/gohugoio/gift]
package resize

import (
	"image"

	"github.com/gohugoio/gift"
)

// InterpolationFunction sets the desired image filter function
type InterpolationFunction int

const (
	// Nearest-neighbor interpolation using [gift.NearestNeighborResampling]
	NearestNeighbor InterpolationFunction = iota
	// Bilinear interpolation using [gift.LinearResampling]
	Bilinear
	// Bicubic interpolation (with cubic hermite spline) using [gift.CubicResampling]
	Bicubic
	// Mitchell-Netravali interpolation using [gift.CubicResampling]
	MitchellNetravali
	// Lanczos2 uses [gift.LanczosResampling]
	Lanczos2
	// Lanczos3 uses [gift.LanczosResampling]
	Lanczos3
)

func (i InterpolationFunction) resamplefilter() gift.Resampling {
	switch i {
	case NearestNeighbor:
		return gift.NearestNeighborResampling
	case Bilinear:
		return gift.LinearResampling
	case Bicubic:
		return gift.CubicResampling
		// Mitchell-Netravali cubic filter (BC-spline; B=1/3; C=1/3)
	case MitchellNetravali:
		return resamp{
			name:    "MitchellNetravali",
			support: 2.0,
			kernel: func(x float32) float32 {
				x = absf32(x)
				if x < 2.0 {
					return bcspline(x, 1.0/3.0, 1.0/3.0)
				}
				return 0
			},
		}
	case Lanczos2, Lanczos3:
		return gift.LanczosResampling
	}

	// Catmull-Rom - sharp cubic filter (BC-spline; B=0; C=0.5)
	return resamp{
		name:    "CatmullRomResampling",
		support: 2.0,
		kernel: func(x float32) float32 {
			x = absf32(x)
			if x < 2.0 {
				return bcspline(x, 0.0, 0.5)
			}
			return 0
		},
	}
}

// Resize re-implements [github.com/nfnt/resize.Resize]
func Resize(width, height uint, img image.Image, interp InterpolationFunction) image.Image {
	g := gift.New(
		gift.Resize(int(width), int(height), interp.resamplefilter()),
	)
	dst := image.NewRGBA(g.Bounds(img.Bounds()))
	g.Draw(dst, img)

	return dst
}

// The following code is borrowed from https://raw.githubusercontent.com/disintegration/gift/master/resize.go
// MIT licensed.
type resamp struct {
	name    string
	support float32
	kernel  func(float32) float32
}

func (r resamp) String() string {
	return r.name
}

func (r resamp) Support() float32 {
	return r.support
}

func (r resamp) Kernel(x float32) float32 {
	return r.kernel(x)
}

func bcspline(x, b, c float32) float32 {
	if x < 0 {
		x = -x
	}
	if x < 1 {
		return ((12-9*b-6*c)*x*x*x + (-18+12*b+6*c)*x*x + (6 - 2*b)) / 6
	}
	if x < 2 {
		return ((-b-6*c)*x*x*x + (6*b+30*c)*x*x + (-12*b-48*c)*x + (8*b + 24*c)) / 6
	}
	return 0
}

func absf32(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
