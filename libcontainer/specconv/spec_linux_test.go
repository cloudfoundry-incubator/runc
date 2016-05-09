// build +linux

package specconv

import (
	"strings"
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestLinuxCgroupsPathSpecified(t *testing.T) {
	cgroupsPath := "/user/cgroups/path/id"

	spec := &specs.Spec{}
	spec.Linux.CgroupsPath = &cgroupsPath

	opts := &CreateOpts{
		CgroupName:       "ContainerID",
		UseSystemdCgroup: false,
		Spec:             spec,
	}

	cgroup, err := createCgroupConfig(opts)
	if err != nil {
		t.Errorf("Couldn't create Cgroup config: %v", err)
	}

	if cgroup.Path != cgroupsPath {
		t.Errorf("Wrong cgroupsPath, expected '%s' got '%s'", cgroupsPath, cgroup.Path)
	}
}

func TestLinuxCgroupsPathNotSpecified(t *testing.T) {
	spec := &specs.Spec{}
	opts := &CreateOpts{
		CgroupName:       "ContainerID",
		UseSystemdCgroup: false,
		Spec:             spec,
	}

	cgroup, err := createCgroupConfig(opts)
	if err != nil {
		t.Errorf("Couldn't create Cgroup config: %v", err)
	}

	if !strings.HasSuffix(cgroup.Path, "/ContainerID") {
		t.Errorf("Wrong cgroupsPath, expected it to have suffix '%s' got '%s'", "/ContainerID", cgroup.Path)
	}
}

func TestSpecconvExampleValidate(t *testing.T) {
	spec := Example()
	spec.Root.Path = "/"

	opts := &CreateOpts{
		CgroupName:       "ContainerID",
		UseSystemdCgroup: false,
		Spec:             spec,
	}

	config, err := CreateLibcontainerConfig(opts)
	if err != nil {
		t.Errorf("Couldn't create libcontainer config: %v", err)
	}

	validator := validate.New()
	if err := validator.Validate(config); err != nil {
		t.Errorf("Expected specconv to produce valid container config: %v", err)
	}
}

func TestRootlessSpecconvValidate(t *testing.T) {
	spec := Example()
	spec.Root.Path = "/"
	ToRootless(spec)

	opts := &CreateOpts{
		CgroupName:       "ContainerID",
		UseSystemdCgroup: false,
		Spec:             spec,
		Rootless:         true,
	}

	config, err := CreateLibcontainerConfig(opts)
	if err != nil {
		t.Errorf("Couldn't create libcontainer config: %v", err)
	}

	validator := validate.New()
	if err := validator.Validate(config); err != nil {
		t.Errorf("Expected specconv to produce valid rootless container config: %v", err)
	}
}
