package user

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	minId = 0
	maxId = 1<<31 - 1 //for 32-bit systems compatibility
)

var (
	ErrRange = fmt.Errorf("uids and gids must be in range %d-%d", minId, maxId)
)

type User struct {
	Name  string
	Pass  string
	Uid   int
	Gid   int
	Gecos string
	Home  string
	Shell string
}

type Group struct {
	Name string
	Pass string
	Gid  int
	List []string
}

func parseLine(line string, v ...interface{}) {
	if line == "" {
		return
	}

	parts := strings.Split(line, ":")
	for i, p := range parts {
		// Ignore cases where we don't have enough fields to populate the arguments.
		// Some configuration files like to misbehave.
		if len(v) <= i {
			break
		}

		// Use the type of the argument to figure out how to parse it, scanf() style.
		// This is legit.
		switch e := v[i].(type) {
		case *string:
			*e = p
		case *int:
			// "numbers", with conversion errors ignored because of some misbehaving configuration files.
			*e, _ = strconv.Atoi(p)
		case *[]string:
			// Comma-separated lists.
			if p != "" {
				*e = strings.Split(p, ",")
			} else {
				*e = []string{}
			}
		default:
			// Someone goof'd when writing code using this function. Scream so they can hear us.
			panic(fmt.Sprintf("parseLine only accepts {*string, *int, *[]string} as arguments! %#v is not a pointer!", e))
		}
	}
}

func ParsePasswd(passwd io.Reader) ([]User, error) {
	return ParsePasswdFilter(passwd, nil)
}

func ParsePasswdFilter(r io.Reader, filter func(User) bool) ([]User, error) {
	if r == nil {
		return nil, fmt.Errorf("nil source for passwd-formatted data")
	}

	var (
		s   = bufio.NewScanner(r)
		out = []User{}
	)

	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		// see: man 5 passwd
		//  name:password:UID:GID:GECOS:directory:shell
		// Name:Pass:Uid:Gid:Gecos:Home:Shell
		//  root:x:0:0:root:/root:/bin/bash
		//  adm:x:3:4:adm:/var/adm:/bin/false
		p := User{}
		parseLine(line, &p.Name, &p.Pass, &p.Uid, &p.Gid, &p.Gecos, &p.Home, &p.Shell)

		if filter == nil || filter(p) {
			out = append(out, p)
		}
	}

	return out, nil
}

func ParseGroup(group io.Reader) ([]Group, error) {
	return ParseGroupFilter(group, nil)
}

func ParseGroupFilter(r io.Reader, filter func(Group) bool) ([]Group, error) {
	if r == nil {
		return nil, fmt.Errorf("nil source for group-formatted data")
	}

	var (
		s   = bufio.NewScanner(r)
		out = []Group{}
	)

	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		text := s.Text()
		if text == "" {
			continue
		}

		// see: man 5 group
		//  group_name:password:GID:user_list
		// Name:Pass:Gid:List
		//  root:x:0:root
		//  adm:x:4:root,adm,daemon
		p := Group{}
		parseLine(text, &p.Name, &p.Pass, &p.Gid, &p.List)

		if filter == nil || filter(p) {
			out = append(out, p)
		}
	}

	return out, nil
}

type ExecUser struct {
	Uid   int
	Gid   int
	Sgids []int
	Home  string
}

// GetExecUserPath is a wrapper for GetExecUser. It reads data from each of the
// given file paths and uses that data as the arguments to GetExecUser. If the
// files cannot be opened for any reason, the error is ignored and a nil
// io.Reader is passed instead.
func GetExecUserPath(userSpec string, defaults *ExecUser, passwdPath, groupPath string) (*ExecUser, error) {
	passwd, err := os.Open(passwdPath)
	if err != nil {
		passwd = nil
	} else {
		defer passwd.Close()
	}

	group, err := os.Open(groupPath)
	if err != nil {
		group = nil
	} else {
		defer group.Close()
	}

	return GetExecUser(userSpec, defaults, passwd, group)
}

func matchUser(userArg string, users []User) *User {
	// Match the user in the passwd file
	uidArg, uidErr := strconv.Atoi(userArg)
	if uidErr == nil {
		// If the userArg is numeric, always treat it as a UID.
		for _, u := range users {
			if u.Uid == uidArg {
				return &u
			}
		}
	} else {
		// or if the users matches the explicit user
		for _, u := range users {
			if u.Name == userArg {
				return &u
			}
		}
	}

	// No matches
	return nil
}

func uidUser(userArg string, defaultUser User) (User, error) {
	uidArg, err := strconv.Atoi(userArg)
	if err != nil {
		// Not numeric.
		return User{}, fmt.Errorf("unable to find user %s: %v", userArg, ErrNoPasswdEntries)
	}

	// Must be inside valid uid range.
	if uidArg < minId || uidArg > maxId {
		return User{}, ErrRange
	}

	user := defaultUser
	user.Uid = uidArg
	return user, nil
}

func findUser(userArg string, users []User, defaultUser User) (User, error) {
	if userArg == "" {
		return findUser(fmt.Sprintf("%d", defaultUser.Uid), users, defaultUser)
	}

	// First match wins, even if there's more than one matching entry.
	if matchedUser := matchUser(userArg, users); matchedUser != nil {
		return *matchedUser, nil
	}

	// If we can't find a user with the given username, the only other valid
	// option is if it's a numeric username with no associated entry in passwd.
	return uidUser(userArg, defaultUser)
}

func matchGroup(groupArg string, groups []Group) *Group {
	// Match the group in the group file
	gidArg, gidErr := strconv.Atoi(groupArg)
	if gidErr == nil {
		// If the groupArg is numeric, always treat it as a GID.
		for _, g := range groups {
			if g.Gid == gidArg {
				return &g
			}
		}
	} else {
		// or if the groups matches the explicit group
		for _, g := range groups {
			if g.Name == groupArg {
				return &g
			}
		}
	}

	// No group matches
	return nil
}

func gidGroup(groupArg string) (int, error) {
	gidArg, gidErr := strconv.Atoi(groupArg)
	if gidErr != nil {
		// Not numeric.
		return -1, fmt.Errorf("unable to find group %s: %v %s", groupArg, ErrNoGroupEntries, gidErr.Error())
	}

	// Must be inside valid gid range.
	if gidArg < minId || gidArg > maxId {
		return -1, ErrRange
	}

	return gidArg, nil
}

func findPrimaryGroup(groupArg string, groups []Group, defaultGID int) (int, error) {
	if groupArg == "" {
		return defaultGID, nil
	}

	// matchedGroup will be first matching entry from groups
	if matchedGroup := matchGroup(groupArg, groups); matchedGroup != nil {
		return matchedGroup.Gid, nil
	}

	// If we can't find a group with the given name, the only other valid
	// option is if it's a numeric group name with no associated entry in group.
	return gidGroup(groupArg)
}

func supplementaryGroups(username string, groups []Group) []Group {
	if len(groups) == 0 {
		// No groups provided - can't match user groups
		return []Group{}
	}

	// Check if user is a member of this group.
	out := []Group{}
	for _, g := range groups {
		for _, u := range g.List {
			if u == username {
				out = append(out, g)
			}
		}
	}

	return out
}

func findSupplementaryGroups(username string, groups []Group, defaultSgids []int) ([]int, error) {
	if username == "" {
		return defaultSgids, nil
	}

	userGroups := supplementaryGroups(username, groups)
	if len(userGroups) == 0 {
		return defaultSgids, nil
	}

	sgids := make([]int, len(userGroups))
	for i, grp := range userGroups {
		sgids[i] = grp.Gid
	}

	return sgids, nil
}

// GetExecUser parses a user specification string (using the passwd and group
// readers as sources for /etc/passwd and /etc/group data, respectively). In
// the case of blank fields or missing data from the sources, the values in
// defaults is used.
//
// GetExecUser will return an error if a user or group literal could not be
// found in any entry in passwd and group respectively.
//
// Examples of valid user specifications are:
//     * ""
//     * "user"
//     * "uid"
//     * "user:group"
//     * "uid:gid
//     * "user:gid"
//     * "uid:group"
//
// It should be noted that if you specify a numeric user or group id, they will
// not be evaluated as usernames (only the metadata will be filled). So attempting
// to parse a user with user.Name = "1337" will produce the user with a UID of
// 1337.
func GetExecUser(userSpec string, defaults *ExecUser, passwd, group io.Reader) (*ExecUser, error) {
	if defaults == nil {
		defaults = new(ExecUser)
	}

	// Allow for userArg to have either "user" syntax, or optionally "user:group" syntax
	var userArg, groupArg string
	parseLine(userSpec, &userArg, &groupArg)

	var err error
	users := []User{}
	if passwd != nil {
		users, err = ParsePasswd(passwd)
		if err != nil {
			return nil, err
		}
	}

	user, err := findUser(userArg, users, User{
		Uid:  defaults.Uid,
		Gid:  defaults.Gid,
		Home: defaults.Home,
	})
	if err != nil {
		return nil, err
	}

	groups := []Group{}
	if group != nil {
		groups, err = ParseGroup(group)
		if err != nil {
			return nil, err
		}
	}

	gid, err := findPrimaryGroup(groupArg, groups, user.Gid)
	if err != nil {
		return nil, err
	}

	sgids, err := findSupplementaryGroups(user.Name, groups, defaults.Sgids)
	if err != nil {
		return nil, err
	}

	return &ExecUser{
		Uid:   user.Uid,
		Gid:   gid,
		Sgids: sgids,
		Home:  user.Home,
	}, nil
}

// GetAdditionalGroups looks up a list of groups by name or group id
// against the given /etc/group formatted data. If a group name cannot
// be found, an error will be returned. If a group id cannot be found,
// or the given group data is nil, the id will be returned as-is
// provided it is in the legal range.
func GetAdditionalGroups(additionalGroups []string, group io.Reader) ([]int, error) {
	var groups = []Group{}
	if group != nil {
		var err error
		groups, err = ParseGroupFilter(group, func(g Group) bool {
			for _, ag := range additionalGroups {
				if g.Name == ag || strconv.Itoa(g.Gid) == ag {
					return true
				}
			}
			return false
		})
		if err != nil {
			return nil, fmt.Errorf("Unable to find additional groups %v: %v", additionalGroups, err)
		}
	}

	gidMap := make(map[int]struct{})
	for _, ag := range additionalGroups {
		var found bool
		for _, g := range groups {
			// if we found a matched group either by name or gid, take the
			// first matched as correct
			if g.Name == ag || strconv.Itoa(g.Gid) == ag {
				if _, ok := gidMap[g.Gid]; !ok {
					gidMap[g.Gid] = struct{}{}
					found = true
					break
				}
			}
		}
		// we asked for a group but didn't find it. let's check to see
		// if we wanted a numeric group
		if !found {
			gid, err := strconv.Atoi(ag)
			if err != nil {
				return nil, fmt.Errorf("Unable to find group %s", ag)
			}
			// Ensure gid is inside gid range.
			if gid < minId || gid > maxId {
				return nil, ErrRange
			}
			gidMap[gid] = struct{}{}
		}
	}
	gids := []int{}
	for gid := range gidMap {
		gids = append(gids, gid)
	}
	return gids, nil
}

// GetAdditionalGroupsPath is a wrapper around GetAdditionalGroups
// that opens the groupPath given and gives it as an argument to
// GetAdditionalGroups.
func GetAdditionalGroupsPath(additionalGroups []string, groupPath string) ([]int, error) {
	group, err := os.Open(groupPath)
	if err == nil {
		defer group.Close()
	}
	return GetAdditionalGroups(additionalGroups, group)
}
