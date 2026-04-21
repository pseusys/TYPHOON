module wg-daita

go 1.22

require golang.zx2c4.com/wireguard v0.0.0-00010101000000-000000000000

// Points to the Mullvad wireguard-go fork cloned one directory above this module.
// In Docker: /build/wireguard-go (wg-daita lives at /build/wg-daita).
// In CI:     evaluation/protocols/wireguard_daita/wireguard-go (clone target for staticcheck).
replace golang.zx2c4.com/wireguard => ../wireguard-go
