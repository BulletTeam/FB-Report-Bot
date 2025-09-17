module.exports = {
  profileSets: [
    {
      id: "ProfileSet1",
      name: "Profile Set 1",
      steps: [
        {
          label: "See Options",
          selectors: [
            "text:See Options",
            "text:More options",
            "css:button[aria-label='More']",
            "css:div[role='button']:has-text('Options')",
            "xpath://*[@role='menuitem' and contains(.,'See Options')]"
          ],
          recoverySelectors: [
            "css:div[aria-label='Actions for this post']",
            "css:div[aria-label='More actions']"
          ],
          mandatory: true,
          postCheck: "text:Report Profile"
        },
        {
          label: "Report Profile",
          selectors: [
            "text:Report Profile",
            "text:Report",
            "css:a[role='menuitem']:has-text('Report')",
            "xpath://*[@role='menuitem' and contains(.,'Report')]"
          ],
          mandatory: true,
          postCheck: "text:Something about this page"
        },
        {
          label: "Something about this page",
          selectors: [
            "text:Something about this page",
            "text:Report this page",
            "xpath://*[contains(text(),'Something about this page')]"
          ],
          mandatory: true,
          postCheck: "text:Problem involving"
        },
        {
          label: "Problem involving someone under 18",
          selectors: [
            "text:Problem involving someone under 18",
            "text:Under 18",
            "xpath://*[contains(text(),'under 18')]"
          ],
          mandatory: true,
          postCheck: "text:Threatening"
        },
        {
          label: "Threatening to share my nude images",
          selectors: [
            "text:Threatening to share my nude images",
            "text:Threatening to share",
            "xpath://*[contains(text(),'Threatening')]"
          ],
          mandatory: true,
          postCheck: "text:Submit"
        },
        {
          label: "Submit",
          selectors: [
            "text:Submit",
            "css:button:has-text('Submit')",
            "xpath://*[@role='button' and contains(.,'Submit')]"
          ],
          mandatory: true,
          postCheck: "text:Next"
        },
        {
          label: "Next",
          selectors: [
            "text:Next",
            "css:button:has-text('Next')",
            "xpath://*[@role='button' and contains(.,'Next')]"
          ],
          mandatory: true,
          postCheck: "text:Done"
        },
        {
          label: "Done",
          selectors: [
            "text:Done",
            "css:button:has-text('Done')",
            "xpath://*[@role='button' and contains(.,'Done')]"
          ],
          mandatory: true
        }
      ]
    }
  ]
}
