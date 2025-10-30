# This is the running effort for the document.
# print("Hello Group2")
# print("Welcome To Wk1")

# To run this code access terminal from the menu in GitHub.
# To do this first click on "Code Spaces" in the Navigation Bar
# Add you edits there.
# In the GitHub Termanl type: Python3 Group2_Code.py
# This is the difficult part:
# to save your changes to GitHub you will need to use the following commands:
# git add .
# git commit -m "Your Message Here"
# git push

from datetime import datetime


def main():

    print("Welcome to Group 2 MVP")

    # Ask for a character name; removes leading/trailing spaces.
    characterName = input("Enter Character Name: ").strip()

    while True:
        probability = input("Enter Probability (e.g, 0.7 or 70%): ").strip()
        try:

            # If there's a '%', divide by 100 to convert to 0–1.
            # replace("%", " ") removes '%' by turning it into a space,
            # then float(...) parses it.

            percent = float(probability.replace("%", " ")) / (
                100 if "%" in probability else 1
            )
            if 0 <= percent <= 1:
                break

        except ValueError:
            pass

        print("Invalid. Enter 0.00-1.00 or 0-100%.")

    # Print a single summary line:
    # ISO timestamp, characterName shown with its variable name,
    # using f-string debug format {characterName=}, percent formatted to 3 decimal places

    print(f"{datetime.now().isoformat()} | {characterName=} | percent={percent:.3f}")


if __name__ == "__main__":
    main()
