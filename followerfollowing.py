import re

def extract_usernames_from_html(html_text):
    pattern = r'https://www\.instagram\.com/([^/"]+)'
    usernames = re.findall(pattern, html_text)
    return usernames

def find_unfollowers(followers, following):
    unfollowers = [user for user in following if user not in followers]
    return unfollowers

if __name__ == "__main__":
    # Read content from 'following.html' and 'followers_1.html'
    with open('following.html', 'r', encoding='utf-8') as following_file:
        following_text = following_file.read()

    with open('followers_1.html', 'r', encoding='utf-8') as followers_file:
        followers_text = followers_file.read()

    # Extract usernames from HTML contents
    followers = extract_usernames_from_html(followers_text)
    following = extract_usernames_from_html(following_text)

    # Find unfollowers
    unfollowers = find_unfollowers(followers, following)

    # Print the number of unfollowers
    print(f"Number of people you follow who don't follow you back: {len(unfollowers)}")
    print("--------------------------------------------------------------------------")
    # Print unfollowers
    print("The list of people you follow who don't follow you back:")
    for username in unfollowers:
        print(username)
