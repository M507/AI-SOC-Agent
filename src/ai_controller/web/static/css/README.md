# CSS File Organization

This directory contains the CSS styles for the AI Controller web interface, organized into logical modules for easier maintenance and updates.

## File Structure

### `base.css`
**Purpose:** Base styles, CSS reset, body, and container styles
- Global reset rules (`*`, `margin`, `padding`, `box-sizing`)
- Body styling (font, background, colors, overflow)
- Container layout

### `layout.css`
**Purpose:** Main layout structure, sidebar, header, and content areas
- Main layout with sidebar (`main-layout`, `sidebar`, `main-panel`)
- Navigation items (`nav-item`, `nav-label`)
- Header styling (`header`, `header-actions`)
- Content area (`content-area`, `session-content`, `session-header`)
- Empty state messages (`no-session`)

### `buttons.css`
**Purpose:** All button variants and sizes
- Base button styles (`.btn`)
- Button variants: primary, secondary, danger
- Button sizes: small (`.btn-sm`)
- Hover states for all variants

### `tabs.css`
**Purpose:** Tab container, tabs, and tab-related elements
- Tab container and header (`tabs-container`, `tabs-header`)
- Tab groups and labels (`tab-group`, `tab-group-label`)
- Individual tabs (`tab`, `tab.active`)
- Tab badges and close buttons (`tab-badge`, `tab-close`)

### `status.css`
**Purpose:** Status badge indicators for sessions and autoruns
- Base status badge styles
- Status variants: pending, running, completed, failed, stopped

### `terminal.css`
**Purpose:** Terminal container, terminal output, and command input
- Terminal container and terminal display
- Terminal line styles (command, output, error, success, timestamp)
- Command input container and input field

### `autorun.css`
**Purpose:** Autorun-specific layout and terminal scrolling behavior
- Autorun content layout with fixed header and scrollable terminal
- Autorun terminal container overrides
- Autorun prompt display styling
- Scrolling behavior for autorun terminal (only terminal scrolls, header stays fixed)

### `modal.css`
**Purpose:** Dialog modals for creating sessions and autoruns
- Modal overlay and content container
- Modal header, body, and footer
- Form inputs within modals
- Close button styling

### `settings.css`
**Purpose:** Settings page layout and form elements
- Settings content and body layout
- Toggle switches and labels
- Help text and tooltips
- Help link styling

### `scrollbar.css`
**Purpose:** Custom scrollbar appearance
- Webkit scrollbar styling (width, track, thumb)
- Scrollbar hover states

## Loading Order

The CSS files are loaded in the following order in `index.html`:
1. `base.css` - Foundation styles
2. `layout.css` - Layout structure
3. `buttons.css` - Button components
4. `tabs.css` - Tab components
5. `status.css` - Status indicators
6. `terminal.css` - Terminal components
7. `autorun.css` - Autorun-specific overrides
8. `modal.css` - Modal components
9. `settings.css` - Settings page
10. `scrollbar.css` - Scrollbar styling

This order ensures that more specific styles (like `autorun.css`) can override base styles when needed.

## Making Changes

When updating styles:
- **Layout changes:** Edit `layout.css`
- **Button styling:** Edit `buttons.css`
- **Terminal appearance:** Edit `terminal.css`
- **Autorun scrolling/layout:** Edit `autorun.css`
- **Modal dialogs:** Edit `modal.css`
- **Settings page:** Edit `settings.css`
- **Global changes:** Edit `base.css` or `scrollbar.css`

## Versioning

Each CSS file includes a version query parameter in the HTML (`?v=1`) to enable cache busting when styles are updated. Increment the version number when making changes to force browsers to reload the updated styles.

