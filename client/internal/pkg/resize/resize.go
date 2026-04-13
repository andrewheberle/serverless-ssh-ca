// This package re-implements [github.com/nfnt/resize.Resize] using [github.com/disintegration/imaging]
package resize

import (
	"image"

	"github.com/disintegration/imaging"
)

// InterpolationFunction sets the desired image filter function
type InterpolationFunction int

const (
	// Nearest-neighbor interpolation using [imaging.NearestNeighbor]
	NearestNeighbor InterpolationFunction = iota
	// Bilinear interpolation using [imaging.Linear]
	Bilinear
	// Bicubic interpolation (with cubic hermite spline) using [imaging.Hermite]
	Bicubic
	// Mitchell-Netravali interpolation using [imaging.MitchellNetravali]
	MitchellNetravali
	// Lanczos2 uses [imaging.Lanczos]
	Lanczos2
	// Lanczos3 uses [imaging.Lanczos]
	Lanczos3
)

func (i InterpolationFunction) resamplefilter() imaging.ResampleFilter {
	switch i {
	case NearestNeighbor:
		return imaging.NearestNeighbor
	case Bilinear:
		return imaging.Linear
	case Bicubic:
		return imaging.Hermite
	case MitchellNetravali:
		return imaging.MitchellNetravali
	case Lanczos2, Lanczos3:
		return imaging.Lanczos
	}

	return imaging.CatmullRom
}

// Resize re-implements the [github.com/nfnt/resize.Resize]
func Resize(width, height uint, img image.Image, interp InterpolationFunction) image.Image {
	return imaging.Resize(img, int(width), int(height), interp.resamplefilter())
}
