# Instagram Follower Analyzer 👥

A simple Python tool that helps you discover who doesn't follow you back on Instagram.

[![Watch Tutorial](https://img.shields.io/badge/Watch-Tutorial-red?style=for-the-badge&logo=youtube)](https://youtu.be/ZugkbNARgnU)

## 🔍 What This Tool Does

This tool analyzes your Instagram account data to identify:
- People who don't follow you back
- The total count of non-reciprocal followers

## 📋 Prerequisites

- Python 3.6 or higher
- Your Instagram data export files

## 🚀 Installation

1. **Clone or download this repository**
   ```
   git clone https://github.com/yourusername/instagram-follower-analyzer.git
   ```
   
   Or download and extract the ZIP file from the repository.

2. **Navigate to the project directory**
   ```
   cd instagram-follower-analyzer
   ```

## 📥 Getting Your Instagram Data

1. Go to your Instagram account settings through the Account Center:
   - Visit https://accountscenter.instagram.com/info_and_permissions/?theme=dark
   - Select "Download your information"
   - Request a download of your data (select HTML format)
   - Wait for Instagram to prepare your data (you'll receive an email)

2. Once you receive the email, download your data as a ZIP file

3. Extract the ZIP file to a folder on your computer

4. Navigate to: `connections → followers-and-following`

5. Locate the `following.html` and `followers_1.html` files

## 💻 Usage

1. **Prepare your data files**
   - Remove the example files from the project folder
   - Copy your personal `following.html` and `followers_1.html` files into the project folder

2. **Run the script**
   ```
   python followerfollowing.py
   ```

3. **View the results**
   - The terminal will display the number of people who don't follow you back
   - It will list all usernames that don't follow you back

## 📊 Example Output

```
Number of people you follow who don't follow you back: 3
--------------------------------------------------------------------------
The list of people you follow who don't follow you back:
accountthatdoesntfollowyouback
accountthatdoesntfollowyouback2
accountthatdoesntfollowyouback3
```

## 🛠️ How It Works

This tool uses Python's regular expression capabilities to:
1. Extract Instagram usernames from your HTML data files
2. Compare your "following" list against your "followers" list
3. Identify accounts that appear in your following list but not in your followers list

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue if you have suggestions for improvements.

## ⚠️ Disclaimer

This tool is for personal use only and is not affiliated with Instagram. Use responsibly and in accordance with Instagram's Terms of Service.
