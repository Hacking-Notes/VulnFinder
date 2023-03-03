from termcolor import colored


class Printer:
    def __init__(self, mode = True):
        self.colored_mode = mode

    def set_mode(self, mode: bool):
        self.colored_mode = mode

    def print(self, message):

        # Colored output based on message marks and color mode.

        if not self.colored_mode:
            print(message)

        else:
            try:
                status = message[0:3]
            except:
                print(message)
                return 0
            if status == "[!]":
                print(colored(message[4:], 'white', 'on_red'))
            elif status == "[+]":
                print(colored(message[4:], 'white', 'on_green'))
            elif status == "[-]":
                print(colored(message[4:], 'red', 'on_yellow'))
            elif status == "[&]":
                print(colored(message[4:], 'white', 'on_cyan', attrs=["bold"]))
            elif status == "[.]":
                print(colored(message[4:], 'grey', 'on_white'))
            elif status == "[~]":
                print(colored(message[4:], 'white', attrs=["bold"]))
            else:
                print(message)

