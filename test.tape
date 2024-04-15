# Steps to install vhs
# sudo apt install -y ffmpeg snapd
# sudo snap install ttyd --classic
# wget https://github.com/b-per/vhs/releases/download/v0.7.1/vhs_0.7.1_Linux_x86_64.tar.gz
# tar -xvz vhs_0.7.1_Linux_x86_64.tar.gz
# mv vhs_0.7.1_Linux_x86_64/vhs ~/.local/bin

Output demo.gif
Set Shell fish

# Set up a 1200x600 terminal with 46px font.
Set FontSize 25
Set Width 1500
Set Height 1000
Set BorderRadius 10
Set WaitPattern />$/
Set WaitTimeout 2m

Type "secator --help"
Sleep 500ms
Enter
Wait

Type "# here are some things secator can do ..."
Enter
Sleep 3s

#-------#
# TASKS #
#-------#
Type "# Run simple tasks ..."
Sleep 3s

Type "secator x httpx testphp.vulnweb.com"
Sleep 500ms
Enter
Wait

Type "# with mutualized input options ..."
Sleep 3s

Type "secator x katana testphp.vulnweb.com -rl 100 -threads 50 -timeout 10 -header Content-Type:text/html"
Sleep 2s
Left 
Back