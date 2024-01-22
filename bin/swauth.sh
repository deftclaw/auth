# Switch TOTP keys : 1705082356
function swauth() {
  valid_leaves=(admin aws gh lp ms ns test zoho heroku aws_root)
  case $# in
    0)
      ln -sf $HOME/.config/ms.yml $HOME/.config/otp.yml
    ;;
    1)
      [[ "${valid_leaves[@]}" =~ "$1" ]] && ln -sf $HOME/.config/$1.yml $HOME/.config/otp.yml \
        || error "$1 is not a valid keyname"
    ;;
    *) 
      error 'Expected 1 or 0 arguments\nUsage: swauth [key_name]\n  Without a keyname swauth sets default MicroSoft'
    ;;
  esac

  ruby /usr/bin/auth.rb|tee /dev/fd/2|ag -v 'Passphrase'|awk -F ': ' '{print $NF}'|xclip -sel clip
}

# function new_totp() {
#   
# }
