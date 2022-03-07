// +build tools

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

func main() {
	filter := getFilter()
	versions := getModFileData()
	targets := getToolsData()

	for _, target := range targets {
		for moduleName, version := range versions {
			if !strings.HasPrefix(target, moduleName) {
				continue
			}
			if len(filter) > 0 && !filter[moduleName] {
				continue
			}
			execGoInstall(target, version)
			break
		}
	}
}

func getFilter() map[string]bool {
	filter := make(map[string]bool)
	for idx, arg := range os.Args {
		if idx == 0 {
			continue
		}
		filter[arg] = true
	}
	return filter
}

func getModFileData() map[string]string {
	bytes, err := ioutil.ReadFile("go.mod")
	if err != nil {
		panic(err)
	}
	versions := map[string]string{}
	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "module"):
		case !strings.Contains(line, "/"):
		case strings.Contains(line, "indirect"):
		default:
			targets := strings.Split(strings.TrimSpace(line), " ")
			if len(targets) >= 2 {
				versions[targets[0]] = targets[1]
			}
		}
	}
	return versions
}

func getToolsData() []string {
	bytes, err := ioutil.ReadFile("./tools/tools.go")
	if err != nil {
		panic(err)
	}
	targets := []string{}
	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "_") {
			continue
		}
		line = strings.ReplaceAll(line, "_", "")
		line = strings.ReplaceAll(line, "\"", "")
		targets = append(targets, strings.TrimSpace(line))
	}
	return targets
}

func execGoInstall(target, version string) {
	targetModule := target + "@" + version
	execBin("go", "install", targetModule)
	fmt.Printf("installed %s\n", targetModule)
}

func execBin(binary string, args ...string) {
	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	// fmt.Printf("Env: %v\n", cmd.Env)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := stdout.String()
	if err != nil {
		fmt.Printf("Stdout: %s", output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
		fmt.Printf("Stderr: %s\n", stderr.String())
	} else if len(output) > 0 {
		fmt.Printf("%s", output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}
}
