package main

import "strings"

func promptLabel(profileName string) string {
	const maxProfileRunes = 40

	var label strings.Builder
	label.WriteString("rgw:")
	for _, character := range profileName {
		if label.Len() >= len("rgw:")+maxProfileRunes {
			break
		}
		switch {
		case character >= 'a' && character <= 'z':
			label.WriteRune(character)
		case character >= 'A' && character <= 'Z':
			label.WriteRune(character)
		case character >= '0' && character <= '9':
			label.WriteRune(character)
		case strings.ContainsRune("-._@/", character):
			label.WriteRune(character)
		default:
			label.WriteByte('-')
		}
	}
	return label.String()
}

const bashPromptInit = `if [ -r "$HOME/.bashrc" ]; then
  . "$HOME/.bashrc"
fi

__radosgw_assume_prompt_prefix='\[\e[38;5;75m\]['"${RADOSGW_ASSUME_PROMPT_LABEL}"']\[\e[0m\] '
__radosgw_assume_prompt() {
  local __radosgw_assume_last_status=$?
  case $PS1 in
    "$__radosgw_assume_prompt_prefix"*) ;;
    *) PS1="${__radosgw_assume_prompt_prefix}${PS1}" ;;
  esac
  return "$__radosgw_assume_last_status"
}

case "$(declare -p PROMPT_COMMAND 2>/dev/null)" in
  "declare -a "*) PROMPT_COMMAND+=(__radosgw_assume_prompt) ;;
  *)
    case ";${PROMPT_COMMAND:-};" in
      *";__radosgw_assume_prompt;"*) ;;
      *) PROMPT_COMMAND="${PROMPT_COMMAND:+${PROMPT_COMMAND};}__radosgw_assume_prompt" ;;
    esac
    ;;
esac
__radosgw_assume_prompt

command rm -f -- "$RADOSGW_ASSUME_INIT_FILE" 2>/dev/null
command rmdir -- "$RADOSGW_ASSUME_INIT_DIR" 2>/dev/null
unset RADOSGW_ASSUME_INIT_FILE RADOSGW_ASSUME_INIT_DIR
`

const zshEnvironmentInit = `typeset __radosgw_assume_init_dir=$ZDOTDIR
if [[ -n ${RADOSGW_ASSUME_ORIGINAL_ZDOTDIR_SET-} ]]; then
  ZDOTDIR=$RADOSGW_ASSUME_ORIGINAL_ZDOTDIR
  export ZDOTDIR
  typeset __radosgw_assume_original_zshenv=$ZDOTDIR/.zshenv
else
  unset ZDOTDIR
  typeset __radosgw_assume_original_zshenv=$HOME/.zshenv
fi
if [[ -r $__radosgw_assume_original_zshenv ]]; then
  source "$__radosgw_assume_original_zshenv"
fi
if [[ -n ${ZDOTDIR+x} ]]; then
  RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR=$ZDOTDIR
  export RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR
  RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR_SET=1
  export RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR_SET
else
  unset RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR_SET
fi
ZDOTDIR=$__radosgw_assume_init_dir
export ZDOTDIR
unset __radosgw_assume_init_dir __radosgw_assume_original_zshenv
`

const zshPromptInit = `typeset __radosgw_assume_init_dir=$ZDOTDIR
if [[ -n ${RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR_SET-} ]]; then
  ZDOTDIR=$RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR
  export ZDOTDIR
  typeset __radosgw_assume_original_zshrc=$ZDOTDIR/.zshrc
else
  unset ZDOTDIR
  typeset __radosgw_assume_original_zshrc=$HOME/.zshrc
fi
if [[ ${HISTFILE-} == "$__radosgw_assume_init_dir/"* ]]; then
  HISTFILE="${ZDOTDIR:-$HOME}/${HISTFILE#${__radosgw_assume_init_dir}/}"
fi
if [[ -r $__radosgw_assume_original_zshrc ]]; then
  source "$__radosgw_assume_original_zshrc"
fi

if (( $+functions[p10k] && $+parameters[POWERLEVEL9K_LEFT_PROMPT_ELEMENTS] )); then
  prompt_radosgw_assume() {
    p10k segment -b '' -f 75 -t "[$RADOSGW_ASSUME_PROMPT_LABEL]"
  }
  if (( ${POWERLEVEL9K_LEFT_PROMPT_ELEMENTS[(I)radosgw_assume]} == 0 )); then
    typeset -ga POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(radosgw_assume $POWERLEVEL9K_LEFT_PROMPT_ELEMENTS)
  fi
  p10k reload
else
  typeset -g __radosgw_assume_prompt_prefix='%F{75}['${RADOSGW_ASSUME_PROMPT_LABEL}']%f '
  __radosgw_assume_prompt() {
    typeset last_status=$?
    if [[ $PROMPT != "$__radosgw_assume_prompt_prefix"* ]]; then
      PROMPT="${__radosgw_assume_prompt_prefix}${PROMPT}"
    fi
    return $last_status
  }
  autoload -Uz add-zsh-hook
  add-zsh-hook precmd __radosgw_assume_prompt
  __radosgw_assume_prompt
fi

command rm -f -- "$__radosgw_assume_init_dir/.zshenv" "$__radosgw_assume_init_dir/.zshrc" 2>/dev/null
command rmdir -- "$__radosgw_assume_init_dir" 2>/dev/null
unset __radosgw_assume_init_dir __radosgw_assume_original_zshrc
unset RADOSGW_ASSUME_INIT_DIR RADOSGW_ASSUME_ORIGINAL_ZDOTDIR RADOSGW_ASSUME_ORIGINAL_ZDOTDIR_SET
unset RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR RADOSGW_ASSUME_EFFECTIVE_ZDOTDIR_SET
`

const posixPromptInit = `if [ -n "${RADOSGW_ASSUME_ORIGINAL_ENV_SET:-}" ]; then
  ENV=$RADOSGW_ASSUME_ORIGINAL_ENV
  export ENV
  if [ -r "$ENV" ]; then
    . "$ENV"
  fi
else
  unset ENV
fi

case $PS1 in
  "[$RADOSGW_ASSUME_PROMPT_LABEL] "*) ;;
  *) PS1="[$RADOSGW_ASSUME_PROMPT_LABEL] ${PS1}" ;;
esac

command rm -f -- "$RADOSGW_ASSUME_INIT_FILE" 2>/dev/null
command rmdir -- "$RADOSGW_ASSUME_INIT_DIR" 2>/dev/null
unset RADOSGW_ASSUME_INIT_FILE RADOSGW_ASSUME_INIT_DIR
unset RADOSGW_ASSUME_ORIGINAL_ENV RADOSGW_ASSUME_ORIGINAL_ENV_SET
`
