//go:build tray

//go:generate go-winres make --product-version=git-tag --file-version=git-tag

package main

// This is only here to trigger the generation of the required syso file for
// the Windows tray application during the build process
