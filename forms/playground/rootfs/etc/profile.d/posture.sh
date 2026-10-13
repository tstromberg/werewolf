# Login shells (ash and bash) read /etc/profile.d through /etc/profile.
# Show a fresh summary only in the interactive login terminal.
case $- in
    *i*)
        if [ -t 1 ]; then
            /usr/lib/werewolf/posture --summary || :
        fi
        ;;
esac
