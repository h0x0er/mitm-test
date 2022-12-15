package main

import (
	"fmt"
	"os/exec"
)

// const (
// 	natTable        = "nat"
// 	mitmproxyuser   = "mitmproxyuser"
// 	match           = "-m"
// 	owner           = "owner"
// 	not             = "!"
// 	uidOwner        = "--uid-owner"
// 	redirect        = "REDIRECT"
// 	toPort          = "--to-port"
// 	interceptorFile = "/home/mitmproxyuser/interceptor.py"
// )

// func prepareInterceptorScript(allowedPaths string) error {

// 	interceptor := `
// import mitmproxy
// from os import system
// from mitmproxy import http


// class Interceptor:

// 	def request(self, flow: mitmproxy.http.HTTPFlow):

// 		allowed_paths = {"api.github.com":["/repos/step-security/harden-runner"],"github.com":["/step-security/harden-runner/git-upload-pack","/step-security/harden-runner/info/refs?service=git-upload-pack"], "google.com": ["/search"]}

// 		host = flow.request.pretty_host
// 		path = flow.request.path
// 		url = flow.request.url
// 		method = flow.request.method
// 		system(f"echo 'Intercepted: Method: {method}; Domain: {host}; Path: {path}' >> /tmp/mitm-logs")
// 		if path not in allowed_paths[host]:
// 			resp = f"StepSecurity: invalid {path} for {host}"
// 			system(f"echo 'Intercepted: Method: {method}; Domain: {host}; Path: {path}' >> /tmp/blocked-paths")
// 			flow.response = http.Response.make(
// 				200,
// 				resp,
// 				{"Content-Type": "text/html"},
// 			)
// 			return 
		
		

// addons = [Interceptor()]
// 	`

// 	err := ioutil.WriteFile(interceptorFile, []byte(interceptor), 0777)

// 	return err

// }

// type MitmProxy struct{}

// func (mitm *MitmProxy) install() error {

// 	installOneLiner := `wget "https://snapshots.mitmproxy.org/9.0.1/mitmproxy-9.0.1-linux.tar.gz" -O "/tmp/mitmproxy.tar.gz" -q;mkdir -p "/tmp/mitm";tar -xf "/tmp/mitmproxy.tar.gz" -C "/tmp/mitm";sudo mv "/tmp/mitm/mitmdump" "/usr/local/bin"`

// 	_, err := exec.Command("/bin/sh", "-c", installOneLiner).Output()
// 	if err != nil {
// 		return fmt.Sprintf("error installing mitmproxy: %v", err)
// 	}
// 	return nil
// }


// func (mitm *MitmProxy) start() string {

// 	var err error
// 	startOneLiner := fmt.Sprintf("sudo -u mitmproxyuser -H sh -c '/usr/local/bin/mitmdump --mode transparent -s %s&'", interceptorFile)

// 	_, err = exec.Command("/bin/sh", "-c", startOneLiner).Output()
// 	if err != nil {
// 		return fmt.Sprintf("unable to start mitmdump: %v", err)
// 	}

// 	return ""

// }

// func (mitm *MitmProxy) setupCertificate() error {

// 	var err error


// 	certs := `sudo cp /home/mitmproxyuser/.mitmproxy/mitmproxy-ca-cert.cer /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt;sudo update-ca-certificates`

// 	certOutput, err := exec.Command("/bin/sh", "-c", certs).Output()
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println(string(certOutput))
// 	return nil
// }


// func (mitm *MitmProxy) Run() string {
// 	var err error
// 	err = mitm.install()
// 	if err != nil {
// 		return fmt.Sprintf("%v", err)
// 	}
// 	// err = mitm.setupTransparent(firewall)
// 	// if err != nil {
// 	// 	return err
// 	// }

// 	err = prepareInterceptorScript("{dictionary of allowed paths}")
// 	if err != nil {
// 		// _ = mitm.revertTransparent(firewall)
// 		return fmt.Sprintf("unable to prepare interceptor script: %v", err)
// 	}


// 	err = mitm.start()
// 	if err != nil {
// 		// _ = mitm.revertTransparent(firewall)
// 		return fmt.Sprintf("unable to start mitmproxy: %v", err)

// 	}

// 	err = mitm.setupCertificate()
// 	if err != nil {
// 		return fmt.Sprintf("unable to setup certificates: %v", err)
		
// 	}


// 	return ""

// }


func main(){
	var resp []byte
	installOneLiner := `wget "https://snapshots.mitmproxy.org/9.0.1/mitmproxy-9.0.1-linux.tar.gz" -O "/tmp/mitmproxy.tar.gz" -q;mkdir -p "/tmp/mitm";tar -xf "/tmp/mitmproxy.tar.gz" -C "/tmp/mitm";sudo mv "/tmp/mitm/mitmdump" "/usr/local/bin"`
	resp, _ = exec.Command("/bin/sh", "-c", installOneLiner).Output()
	fmt.Println(string(resp))


	setupOneLiner := `sudo useradd mitmproxyuser;mkdir /home/mitmproxyuser;sudo chown -R mitmproxyuser /home/mitmproxyuser`

	resp, _ = exec.Command("/bin/sh", "-c", setupOneLiner).Output()
	
	fmt.Println(string(resp))

	startOneLiner := fmt.Sprintf("sudo -u mitmproxyuser -H sh -c '/usr/local/bin/mitmdump&'")
	resp , _ = exec.Command("/bin/sh", "-c", startOneLiner).Output()
	fmt.Println(string(resp))

	killOneLiner := fmt.Sprintf("kill `pidof mitmdump`")
	resp, _ = exec.Command("/bin/sh", "-c", killOneLiner).Output()
	fmt.Println(string(resp))

	certs := `sudo cp /home/mitmproxyuser/.mitmproxy/mitmproxy-ca-cert.cer /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt;sudo update-ca-certificates`

	certOutput, err := exec.Command("/bin/sh", "-c", certs).Output()
	fmt.Println(string(certOutput))
	fmt.Println(err)


	
}