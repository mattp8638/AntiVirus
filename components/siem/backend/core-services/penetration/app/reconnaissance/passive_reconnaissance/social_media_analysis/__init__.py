import requests
from bs4 import BeautifulSoup
import re
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
    
    except Exception as e:
        return {"error": f"Error scraping Twitter: {e}"}
    
    return tweets

# Example usage
if __name__ == "__main__":
    # Example: Scrape LinkedIn for employees
    company_name = "Example Corp"
    linkedin_results = scrape_linkedin(company_name)
    logger.info(f"LinkedIn Results for {company_name}:")
    for employee in linkedin_results:
        logger.info(f"Name: {employee['name']}, Job Title: {employee['job_title']}, Profile: {employee['profile_link']}")
    
    # Example: Scrape tweets for a keyword
    keyword = "Example Corp breach"
    twitter_results = extract_tweets(keyword, num_tweets=5)
    logger.info(f"\nTwitter Results for '{keyword}':")
    for tweet in twitter_results:
        logger.info(f"Username: {tweet['username']}, Content: {tweet['content']}, Timestamp: {tweet['timestamp']}")
