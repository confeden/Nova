//go:build !nomasque

package main

import "nova-pc/nova-go/masque"

func init() {
	register(group{
		name: "masque",
		help: "Cloudflare MASQUE: register | enroll | socks | probe | check",
		run: func(args []string) int {
			return masque.Main(args, version)
		},
	})
}
