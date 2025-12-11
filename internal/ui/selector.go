package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
)

// bellSkipper implements an io.WriteCloser that skips the terminal bell character.
type bellSkipper struct {
	w io.Writer
}

func (bs *bellSkipper) Write(b []byte) (int, error) {
	const charBell = 7 // bell control character
	if len(b) == 1 && b[0] == charBell {
		return 0, nil
	}
	return bs.w.Write(b)
}

func (bs *bellSkipper) Close() error {
	return nil
}

// SelectProfileInteractively shows an interactive profile selector
func SelectProfileInteractively(profiles []string) (string, error) {
	if len(profiles) == 0 {
		return "", fmt.Errorf("no profiles found in ~/.aws/config")
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}",
		Active:   "{{ \">\" | cyan }} {{ . | cyan | bold }}",
		Inactive: "   {{ . | white }}",
		Selected: "\U00002713 {{ . | cyan | bold }}",
	}

	prompt := promptui.Select{
		Label:        "Please select the profile you would like to assume:",
		Items:        profiles,
		Templates:    templates,
		Size:         10,
		HideHelp:     false,
		Stdout:       &bellSkipper{os.Stderr},
		HideSelected: false,
		Searcher: func(input string, index int) bool {
			profile := profiles[index]
			name := strings.ReplaceAll(strings.ToLower(profile), " ", "")
			input = strings.ReplaceAll(strings.ToLower(input), " ", "")
			return strings.Contains(name, input)
		},
	}

	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return result, nil
}
