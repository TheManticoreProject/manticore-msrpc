package utils

import (
	"fmt"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	epm "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/tcp"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Transport selects how the endpoint mapper is reached.
const (
	// TransportTCP is ncacn_ip_tcp: DCE/RPC straight over TCP (default port 135).
	TransportTCP = "tcp"
	// TransportSMB is ncacn_np: DCE/RPC over the \pipe\epmapper SMB named pipe (default
	// port 445), which requires an authenticated SMB session.
	TransportSMB = "smb"
)

// Default endpoint-mapper ports for each transport.
const (
	DefaultTCPPort = 135
	DefaultSMBPort = 445
)

// dialTimeout bounds the TCP connect and each subsequent receive so an unreachable or
// silent host fails promptly instead of hanging.
const dialTimeout = 5 * time.Second

// DefaultPort returns the endpoint-mapper port to use for the given transport when the
// user did not override it (a zero port means "unset").
//
// Parameters:
//
//	transport (string): The transport, "tcp" or "smb".
//	port (int): The user-supplied port, or 0 if not set.
//
// Returns:
//
//	(int): The port to connect to (135 for tcp, 445 for smb, or the override).
func DefaultPort(transport string, port int) int {
	if port != 0 {
		return port
	}
	if transport == TransportSMB {
		return DefaultSMBPort
	}
	return DefaultTCPPort
}

// ConnectEPM opens a connection to the endpoint mapper on the target host, binds the ept
// interface and returns the ndr.Invoker to issue ept calls through along with a cleanup
// closure that tears the whole chain down. The caller should defer the cleanup.
//
// Over the TCP transport (ncacn_ip_tcp) the endpoint mapper is typically reachable
// unauthenticated; over the SMB transport (ncacn_np) an authenticated session to the
// IPC$ share is required to open \pipe\epmapper.
//
// This is a stopgap: the framework has no high-level endpoint mapper client yet (unlike
// ms_rrp.RemoteRegistry for the registry), so the transport/bind/cleanup plumbing lives
// here. It should be replaced by that client once it lands
// (https://github.com/TheManticoreProject/Manticore/issues/630).
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The endpoint mapper port, or 0 for the per-transport default.
//	transport (string): The transport to use, "tcp" or "smb".
//	creds (*credentials.Credentials): The credentials for authentication (smb transport).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	(ndr.Invoker): The bound endpoint mapper client.
//	(func()): A cleanup closure releasing the client and any SMB session.
//	(error): An error if any step of the connection fails, nil otherwise.
func ConnectEPM(host string, port int, transport string, creds *credentials.Credentials, debug bool) (ndr.Invoker, func(), error) {
	switch transport {
	case TransportTCP, "":
		return connectEPMOverTCP(host, DefaultPort(TransportTCP, port), debug)
	case TransportSMB:
		return connectEPMOverSMB(host, DefaultPort(TransportSMB, port), creds, debug)
	default:
		return nil, nil, fmt.Errorf("unknown transport %q (expected %q or %q)", transport, TransportTCP, TransportSMB)
	}
}

// connectEPMOverTCP binds the endpoint mapper over ncacn_ip_tcp.
func connectEPMOverTCP(host string, port int, debug bool) (ndr.Invoker, func(), error) {
	if debug {
		logger.Debug(fmt.Sprintf("Connecting to endpoint mapper at %s:%d over ncacn_ip_tcp", host, port))
	}

	t := tcp.New(host, port)
	t.SetTimeout(dialTimeout)

	c := client.NewClient(t)
	if err := c.Bind(epm.SyntaxID()); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("error binding the endpoint mapper interface on %s:%d: %s", host, port, err)
	}

	if debug {
		logger.Debug(fmt.Sprintf("Endpoint mapper interface bound on %s:%d", host, port))
	}

	return c, func() { c.Close() }, nil
}

// connectEPMOverSMB binds the endpoint mapper over ncacn_np: dial SMB, authenticate,
// tree-connect to IPC$, open \pipe\epmapper and bind the ept interface over it.
func connectEPMOverSMB(host string, port int, creds *credentials.Credentials, debug bool) (ndr.Invoker, func(), error) {
	if debug {
		logger.Debug(fmt.Sprintf("Dialing SMB to %s:%d", host, port))
	}

	smb, err := smbclient.Dial(host, port, smbclient.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("error dialing SMB to %s:%d: %s", host, port, err)
	}

	if err := smb.Login(creds); err != nil {
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error authenticating to %s: %s", host, err)
	}

	if err := smb.TreeConnect("IPC$"); err != nil {
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error tree-connecting to IPC$ on %s: %s", host, err)
	}

	t, err := smb.RPCTransport(epm.PipeName)
	if err != nil {
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error opening %s on %s: %s", epm.PipeName, host, err)
	}

	c := client.NewClient(t)
	if err := c.Bind(epm.SyntaxID()); err != nil {
		c.Close()
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error binding the endpoint mapper interface on %s: %s", host, err)
	}

	if debug {
		logger.Debug(fmt.Sprintf("Endpoint mapper interface bound on %s over %s", host, epm.PipeName))
	}

	cleanup := func() {
		c.Close()
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
	}

	return c, cleanup, nil
}
