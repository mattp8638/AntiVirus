import requests
from bs4 import BeautifulSoup
import re
import time
from logging_config import get_logger
logger = get_logger(__name__)

def scrape_linkedin(company_name):
    """
    Scrape LinkedIn for employee information related to the target company.
    
    Args:
        company_name (str): The name of the target company.
    
    Returns:
        list: A list of dictionaries containing employee details (name, job title, profile link).
    """
    search_url = f"https://www.linkedin.com/search/results/people/?keywords={company_name}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    employees = []
    
    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find_all("div", class_="entity-result__content")
        
        for result in results:
            name = result.find("span", attrs={"aria-hidden": "true"}).text.strip() if result.find("span", attrs={"aria-hidden": "true"}) else "Unknown Name"
            job_title = result.find("div", class_="entity-result__primary-subtitle").text.strip() if result.find("div", class_="entity-result__primary-subtitle") else "Unknown Job Title"
            profile_link = result.find("a", href=True)["href"] if result.find("a", href=True) else "No Link"
            
            employees.append({
                "name": name,
                "job_title": job_title,
                "profile_link": profile_link
            })
        
        # Add a delay to avoid rate limiting
        time.sleep(5)
    
    except Exception as e:
        return {"error": f"Error scraping LinkedIn: {e}"}
    
    return employees

def extract_tweets(keyword, num_tweets=10):
    """
    Scrape tweets containing a specific keyword from Twitter.
    
    Args:
        keyword (str): The keyword to search for.
        num_tweets (int): The number of tweets to retrieve.
    
    Returns:
        list: A list of dictionaries containing tweet details (username, content, timestamp).
    """
    search_url = f"https://twitter.com/search?q={keyword}&src=typed_query"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    tweets = []
    
    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        tweet_results = soup.find_all("article", attrs={"data-testid": "tweet"})[:num_tweets]
        
        for tweet in tweet_results:
            username = tweet.find("div", attrs={"data-testid": "User-Name"}).text.strip() if tweet.find("div", attrs={"data-testid": "User-Name"}) else "Unknown User"
            content = tweet.find("div", attrs={"lang": True}).text.strip() if tweet.find("div", attrs={"lang": True}) else "No Content"
            timestamp = tweet.find("time")["datetime"] if tweet.find("time") else "No Timestamp"
            
            tweets.append({
                "username": username,
                "content": content,
                "timestamp": timestamp
            })
        
        # Add a delay to avoid rate limiting
        time.sleep(5)
    
    except Exception as e:
        return {"error": f"Error scraping Twitter: {e}"}
    
    return tweets

def scrape_facebook_posts(page_url):
    """
    Scrape publicly available posts from a Facebook page.
    
    Args:
        page_url (str): The URL of the Facebook page to scrape.
    
    Returns:
        list: A list of dictionaries containing post details (username, content, timestamp).
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    posts = []
    
    try:
        response = requests.get(page_url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        post_results = soup.find_all("div", class_="userContentWrapper")[:10]  # Limit to 10 posts
        
        for post in post_results:
            username = post.find("span", class_="fwb").text.strip() if post.find("span", class_="fwb") else "Unknown User"
            content = post.find("div", class_="userContent").text.strip() if post.find("div", class_="userContent") else "No Content"
            timestamp = post.find("abbr")["title"] if post.find("abbr") else "No Timestamp"
            
            posts.append({
                "username": username,
                "content": content,
                "timestamp": timestamp
            })
        
        # Add a delay to avoid rate limiting
        time.sleep(5)
    
    except Exception as e:
        return {"error": f"Error scraping Facebook: {e}"}
    
    return posts

def scrape_instagram_profile(profile_url):
    """
    Scrape publicly available posts from an Instagram profile.
    
    Args:
        profile_url (str): The URL of the Instagram profile to scrape.
    
    Returns:
        list: A list of dictionaries containing post details (caption, timestamp, likes).
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    posts = []
    
    try:
        response = requests.get(profile_url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        post_results = soup.find_all("div", class_="v1Nh3")[:10]  # Limit to 10 posts
        
        for post in post_results:
            caption = post.find("a")["aria-label"] if post.find("a") else "No Caption"
            timestamp = post.find("time")["datetime"] if post.find("time") else "No Timestamp"
            likes = post.find("span", class_="zV_Nj").text.strip() if post.find("span", class_="zV_Nj") else "No Likes"
            
            posts.append({
                "caption": caption,
                "timestamp": timestamp,
                "likes": likes
            })
        
        # Add a delay to avoid rate limiting
        time.sleep(5)
    
    except Exception as e:
        return {"error": f"Error scraping Instagram: {e}"}
    
    return posts

# Unified function to handle all social media scraping
def scrape_social_media(platform, query, num_results=10):
    """
    Unified function to scrape data from various social media platforms.
    
    Args:
        platform (str): The platform to scrape ("linkedin", "twitter", "facebook", "instagram").
        query (str): The search query (e.g., company name, keyword, profile URL).
        num_results (int): The number of results to retrieve (applies to Twitter only).
    
    Returns:
        dict: A dictionary containing scraped data or an error message.
    """
    if platform.lower() == "linkedin":
        return scrape_linkedin(query)
    elif platform.lower() == "twitter":
        return extract_tweets(query, num_results)
    elif platform.lower() == "facebook":
        return scrape_facebook_posts(query)
    elif platform.lower() == "instagram":
        return scrape_instagram_profile(query)
    else:
        return {"error": "Unsupported platform. Supported platforms are 'linkedin', 'twitter', 'facebook', and 'instagram'."}

# Example usage
if __name__ == "__main__":
    # Example: Scrape LinkedIn for employees
    linkedin_results = scrape_social_media("linkedin", "Example Corp")
    logger.info("LinkedIn Results:")
    for employee in linkedin_results:
        logger.info(f"Name: {employee['name']}, Job Title: {employee['job_title']}, Profile: {employee['profile_link']}")
    
    # Example: Scrape tweets for a keyword
    twitter_results = scrape_social_media("twitter", "Example Corp breach", num_results=5)
    logger.info("\nTwitter Results:")
    for tweet in twitter_results:
        logger.info(f"Username: {tweet['username']}, Content: {tweet['content']}, Timestamp: {tweet['timestamp']}")
    
    # Example: Scrape Facebook posts
    facebook_results = scrape_social_media("facebook", "https://www.facebook.com/examplepage")
    logger.info("\nFacebook Results:")
    for post in facebook_results:
        logger.info(f"Username: {post['username']}, Content: {post['content']}, Timestamp: {post['timestamp']}")
    
    # Example: Scrape Instagram profile
    instagram_results = scrape_social_media("instagram", "https://www.instagram.com/exampleprofile")
    logger.info("\nInstagram Results:")
    for post in instagram_results:
        logger.info(f"Caption: {post['caption']}, Timestamp: {post['timestamp']}, Likes: {post['likes']}")
