from playwright.sync_api import sync_playwright
import os

def run_cuj(page):
    print("Navigating to dashboard...")
    page.goto("http://localhost:3000")
    page.wait_for_timeout(2000) # Wait for initial load

    print("Waiting for rules to load...")
    # Wait for the table to potentially populate
    page.wait_for_timeout(3000)

    # Scroll down to see the rules table
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout(1000)

    print("Taking screenshot...")
    page.screenshot(path="/home/jules/verification/screenshots/verification.png", full_page=True)
    page.wait_for_timeout(1000)
    print("CUJ complete.")

if __name__ == "__main__":
    with sync_playwright() as p:
        print("Launching browser...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir="/home/jules/verification/videos",
            viewport={'width': 1280, 'height': 800}
        )
        page = context.new_page()
        try:
            run_cuj(page)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            print("Closing context...")
            context.close()
            browser.close()
