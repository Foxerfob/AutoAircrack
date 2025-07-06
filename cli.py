def confirm(question: str, default = None) -> bool:
    if default == None:
        question = f"{question} [y/n]: "
    elif default:
        question = f"{question} [Y/n]: "
    else:
        question = f"{question} [y/N]: "
    while True:
        answer = input(question).capitalize()
        if answer == "Y":
            return True
        elif answer == "N":
            return False
        elif answer == "":
            if not default == None:
                return default
