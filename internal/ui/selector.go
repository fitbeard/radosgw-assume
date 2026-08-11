package ui

import (
	"errors"
	"fmt"
	"os"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// ErrSelectionCancelled indicates that the interactive selector was dismissed.
var ErrSelectionCancelled = errors.New("profile selection cancelled")

// SelectProfileInteractively shows an interactive profile selector.
func SelectProfileInteractively(profiles []string) (string, error) {
	if len(profiles) == 0 {
		return "", fmt.Errorf("no profiles found in ~/.aws/config")
	}

	keyMap := newProfileSelectorKeyMap()
	var result string
	selector := huh.NewSelect[string]().
		Title("Please select the profile you would like to assume:").
		Description("Press / to filter, Esc or Ctrl+C to cancel.").
		Options(huh.NewOptions(profiles...)...).
		Value(&result).
		Height(min(len(profiles), 10))

	err := huh.NewForm(huh.NewGroup(selector)).
		WithKeyMap(keyMap).
		WithTheme(huh.ThemeFunc(profileSelectorTheme)).
		WithOutput(os.Stderr).
		Run()
	if err != nil {
		return "", normalizeSelectionError(err)
	}

	return result, nil
}

func profileSelectorTheme(isDark bool) *huh.Styles {
	styles := huh.ThemeCharm(isDark)
	cyan := lipgloss.Color("6")
	normal := lipgloss.Color("7")
	muted := lipgloss.Color("8")

	styles.Focused.Title = styles.Focused.Title.Foreground(normal).Bold(false)
	styles.Focused.Description = styles.Focused.Description.Foreground(muted)
	styles.Focused.SelectSelector = styles.Focused.SelectSelector.Foreground(cyan)
	styles.Focused.SelectedOption = styles.Focused.SelectedOption.Foreground(cyan).Bold(true)
	styles.Focused.UnselectedOption = styles.Focused.UnselectedOption.Foreground(normal)
	styles.Focused.TextInput.Cursor = styles.Focused.TextInput.Cursor.Foreground(cyan)
	styles.Focused.TextInput.Prompt = styles.Focused.TextInput.Prompt.Foreground(cyan)
	styles.Focused.TextInput.Text = styles.Focused.TextInput.Text.Foreground(normal)

	styles.Group.Title = styles.Focused.Title
	styles.Group.Description = styles.Focused.Description
	return styles
}

func newProfileSelectorKeyMap() *huh.KeyMap {
	keyMap := huh.NewDefaultKeyMap()
	keyMap.Quit.SetKeys("ctrl+c", "esc")
	keyMap.Quit.SetHelp("esc/ctrl+c", "cancel")
	return keyMap
}

func normalizeSelectionError(err error) error {
	if errors.Is(err, huh.ErrUserAborted) {
		return ErrSelectionCancelled
	}
	return err
}
