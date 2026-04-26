import requests
import time
import concurrent.futures

target_url = "https://auth.ingtech.io/realms/ingtech/.well-known/openid-configuration"
num_requests = 100

def fetch(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

print(f"[*] Starting rate limit test against {target_url}")
print(f"[*] Firing {num_requests} requests simultaneously...\n")

start_time = time.time()

# Use ThreadPoolExecutor to fire requests aggressively
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(fetch, [target_url] * num_requests))

end_time = time.time()

status_counts = {}
for r in results:
    status_counts[r] = status_counts.get(r, 0) + 1

print("--- TEST RESULTS ---")
print(f"Total time: {end_time - start_time:.2f} seconds")
for status, count in status_counts.items():
    print(f"Status Code {status}: Received {count} times")

if 429 in status_counts:
    print("\n[+] SUCCESS: The server successfully rate-limited the attack (429 Too Many Requests).")
elif 200 in status_counts and status_counts[200] == num_requests:
    print("\n[-] VULNERABLE: The server allowed all requests through (200 OK). No rate limiting detected.")
else:
    print("\n[*] UNKNOWN: Check the status codes above to interpret the result.")
