module svgsteg

go 1.26.4

require (
	github.com/andybalholm/brotli v1.2.1
	github.com/fyne-io/oksvg v0.2.0
	github.com/klauspost/compress v1.18.6
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef
)

require (
	golang.org/x/image v0.41.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace github.com/andybalholm/brotli => ./third_party/brotli

replace github.com/fyne-io/oksvg => ./third_party/oksvg
