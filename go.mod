module ids-ips

go 1.22
 
replace golang.org/x/sys => github.com/golang/sys v0.20.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20240604190554-fc45aab8b7f8

require github.com/cilium/ebpf v0.12.3

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.14.1-0.20231108175955-e4099bfacb8c // indirect
)
