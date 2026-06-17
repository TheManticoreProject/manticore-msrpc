package config

import "github.com/TheManticoreProject/Manticore/windows/credentials"

// Config is the shared runtime configuration passed to every mode's Run function.
type Config struct {
	// General
	Debug bool
	// Credentials used to authenticate when the SMB transport is selected.
	Credentials *credentials.Credentials
	// Connection settings for reaching the endpoint mapper.
	Connection Connection
}

// Connection holds the endpoint mapper connection settings.
type Connection struct {
	// Host is the hostname or IP address of the target machine.
	Host string
	// Port is the endpoint mapper port, or 0 for the per-transport default.
	Port int
	// Transport selects how the endpoint mapper is reached: "tcp" (ncacn_ip_tcp) or
	// "smb" (ncacn_np).
	Transport string
}
