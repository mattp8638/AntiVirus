# name: Message the signed-in user
# description: Shows a message box to every signed-in user.
# category: Users
# platforms: windows
# timeout: 300
# param: Message | Message | string | Please save your work: IT maintenance will start shortly. | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
msg.exe * /TIME:300 $Message
'Message sent.'
