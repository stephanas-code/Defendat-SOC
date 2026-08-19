# UI/UX Refinement Plan - AI-NIDS Dashboard

## 1. Sidebar & Global Layout (`src/App.tsx`, `src/components/dashboard/Sidebar.tsx`)
- [ ] **Mobile Menu**: Add a mobile menu toggle in the header.
- [ ] **Responsive Sidebar**: Convert Sidebar to a responsive component that is hidden on mobile and can be toggled via a sheet/drawer.
- [ ] **Main Container**: Fix overflow issues and padding consistency.

## 2. Settings Page Refinement (`src/components/dashboard/SettingsPage.tsx`)
- [ ] **Functional Tabs**: Implement state for settings categories.
- [ ] **Accessible Controls**: Replace custom toggles with functional `Switch` components from Shadcn/UI (or accessible equivalents).
- [ ] **Interactive Slider**: Make the sensitivity range input functional with state.
- [ ] **Mobile Optimization**: Adjust grid and padding for small screens.

## 3. Dashboard Component Polish
- [ ] **StatCards**: Ensure uniform card heights and better mobile spacing.
- [ ] **LiveAlertFeed**: Refine mobile view (less padding, readable font sizes).
- [ ] **MLModels**: Fix chart responsiveness and card layout.

## 4. Interaction Design
- [ ] **Feedback**: Use `sonner` for all success/error interactions.
- [ ] **Loading States**: Add subtle loading indicators where appropriate.
- [ ] **Aria/Accessibility**: Ensure all buttons and inputs have proper labels and focus states.
