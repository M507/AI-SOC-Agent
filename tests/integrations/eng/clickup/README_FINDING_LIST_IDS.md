# Finding ClickUp List IDs

## Important Note

The URLs you provided are **board VIEW URLs**, not **list URLs**. The ClickUp API requires **list IDs**, not view IDs.

Your URLs:
- Visibility Tasks: `https://app.clickup.com/90182069588/v/b/2kzmabam-198`
- Fine-tuning Tasks: `https://app.clickup.com/90182069588/v/b/4-90188208260-2`

The `/v/b/` indicates these are board **views**, not lists.

## Method 1: Find List IDs from ClickUp UI

1. **Open ClickUp** and navigate to your workspace
2. **Find the list** (not the board view):
   - Look for "Visibility Tasks" list in the sidebar
   - Look for "Fine-tuning Tasks" list in the sidebar
3. **Click on the list** to open it
4. **Check the URL** - it should look like:
   ```
   https://app.clickup.com/90182069588/v/li/123456789
   ```
   The number after `/v/li/` is the **list ID** (e.g., `123456789`)

## Method 2: Use ClickUp API (if authentication works)

Run the helper script:
```bash
python tests/integrations/eng/clickup/find_list_ids_simple.py
```

This will list all your lists and their IDs.

## Method 3: Extract from Board View

If you can't find the list directly:

1. Open the board view URL in ClickUp
2. Click on any task in the board
3. Look at the task URL - it will contain the list ID
4. Or click "View List" button on the board to go to the actual list

## What to Put in config.json

Once you have the list IDs, update your `config.json`:

```json
{
  "eng": {
    "provider": "clickup",
    "clickup": {
      "api_token": "your-api-token",
      "fine_tuning_list_id": "123456789",  // <-- List ID (numbers only)
      "engineering_list_id": "987654321",   // <-- List ID (numbers only)
      "timeout_seconds": 30,
      "verify_ssl": true
    }
  }
}
```

**Important**: The list IDs are usually just numbers (like `123456789`), not the alphanumeric strings from the view URLs.

