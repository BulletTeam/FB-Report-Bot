// flows.js
// Updated — every "A → B" split into two steps: parent A then child B.
// Uses text:... selectors as you provided. Replace with css:/xpath: when available.

module.exports = {
  profileSets: [
    // ProfileSet1
    {
      id: "ProfileSet1",
      name: "Profile Set 1",
      steps: [
        // Report 1 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile", "text:Report"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18", "text:Problem involving someone under 18"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images", "text:Threatening to share"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse", "text:Bullying or harassment"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content", "text:Violent content"] },
        { label: "Calling for violence", selectors: ["text:Calling for violence", "text:Calling for violence"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Seems like prostitution", selectors: ["text:Seems like prostitution"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake profile", selectors: ["text:Fake profile", "text:They’re not a real person"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // ProfileSet2
    {
      id: "ProfileSet2",
      name: "Profile Set 2",
      steps: [
        // Report 1 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Bullying or harassment — I don't know them", selectors: ["text:Bullying or harassment — I don't know them", "text:I don't know them"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Showing violence, death or severe injury", selectors: ["text:Showing violence", "text:death", "text:severe injury"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Nudity or sexual activity", selectors: ["text:Nudity", "text:sexual activity"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5 (split)
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake profile", selectors: ["text:Fake profile"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // ProfileSet3
    {
      id: "ProfileSet3",
      name: "Profile Set 3",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Sharing someone’s nude images", selectors: ["text:Sharing someone’s nude images", "text:sharing nude"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Seems like human trafficking", selectors: ["text:Seems like human trafficking", "text:human trafficking", "text:trafficking"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Seems like organised crime", selectors: ["text:Seems like organised crime", "text:organised crime"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake profile", selectors: ["text:Fake profile"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // ProfileSet4
    {
      id: "ProfileSet4",
      name: "Profile Set 4",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Physical abuse", selectors: ["text:Physical abuse", "text:self-harm"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Promoting hate - Posting hateful speech", selectors: ["text:Promoting hate", "text:hateful speech"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "My nude images have been shared", selectors: ["text:My nude images have been shared", "text:images have been shared"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake profile", selectors: ["text:Fake profile"] },
        { label: "Impersonation / fake identity", selectors: ["text:Impersonation", "text:fake identity"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // ProfileSet5
    {
      id: "ProfileSet5",
      name: "Profile Set 5",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Bullying or harassment", selectors: ["text:Bullying or harassment"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Credible threat to safety", selectors: ["text:Credible threat to safety"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Profile", selectors: ["text:Report Profile"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake profile", selectors: ["text:Fake profile"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    }
  ],


  pageSets: [
    // PageSet1
    {
      id: "PageSet1",
      name: "Page Set 1",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page", "text:Report"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Calling for violence", selectors: ["text:Calling for violence"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Seems like prostitution", selectors: ["text:Seems like prostitution"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake page", selectors: ["text:Fake page", "text:They’re not a real page", "text:They’re not a real person"] },
        { label: "They’re not a real page/business/person", selectors: ["text:They’re not a real page", "text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PageSet2
    {
      id: "PageSet2",
      name: "Page Set 2",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Bullying or harassment — I don't know them", selectors: ["text:Bullying or harassment — I don't know them", "text:I don't know them"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Showing violence, death or severe injury", selectors: ["text:Showing violence", "text:death", "text:severe injury"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Nudity or sexual activity", selectors: ["text:Nudity", "text:sexual activity"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake page", selectors: ["text:Fake page", "text:They’re not a real person"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PageSet3
    {
      id: "PageSet3",
      name: "Page Set 3",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Sharing someone’s nude images", selectors: ["text:Sharing someone’s nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Seems like human trafficking", selectors: ["text:Seems like human trafficking", "text:human trafficking"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Seems like organised crime", selectors: ["text:Seems like organised crime"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake page", selectors: ["text:Fake page", "text:They’re not a real person"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PageSet4
    {
      id: "PageSet4",
      name: "Page Set 4",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Physical abuse", selectors: ["text:Physical abuse"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Promoting hate - Posting hateful speech", selectors: ["text:Promoting hate", "text:hateful speech"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "My nude images have been shared", selectors: ["text:My nude images have been shared"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake page", selectors: ["text:Fake page"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PageSet5
    {
      id: "PageSet5",
      name: "Page Set 5",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Bullying or harassment", selectors: ["text:Bullying or harassment"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Credible threat to safety", selectors: ["text:Credible threat to safety"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 5
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Page", selectors: ["text:Report Page"] },
        { label: "Something about this page", selectors: ["text:Something about this page"] },
        { label: "Fake page", selectors: ["text:Fake page"] },
        { label: "They’re not a real person", selectors: ["text:They’re not a real person"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    }
  ],


  postSets: [
    // PostSet1
    {
      id: "PostSet1",
      name: "Post Set 1",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Threatening to share my nude images", selectors: ["text:Threatening to share my nude images"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post"] },
        { label: "Bullying, harassment or abuse", selectors: ["text:Bullying, harassment or abuse"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Calling for violence", selectors: ["text:Calling for violence"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Seems like prostitution", selectors: ["text:Seems like prostitution"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PostSet2
    {
      id: "PostSet2",
      name: "Post Set 2",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post", "text:Something about this"] },
        { label: "Problem involving someone under 18", selectors: ["text:Problem involving someone under 18"] },
        { label: "Seems like sexual exploitation", selectors: ["text:Seems like sexual exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Bullying or harassment — I don't know them", selectors: ["text:Bullying or harassment — I don't know them", "text:I don't know them"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Violent, hateful or disturbing content", selectors: ["text:Violent, hateful or disturbing content"] },
        { label: "Showing violence, death or severe injury", selectors: ["text:Showing violence", "text:death", "text:severe injury"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Adult content", selectors: ["text:Adult content"] },
        { label: "Nudity or sexual activity", selectors: ["text:Nudity", "text:sexual activity"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PostSet3
    {
      id: "PostSet3",
      name: "Post Set 3",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Nudity", selectors: ["text:Nudity", "text:Sexual exploitation"] },
        { label: "Sexual exploitation / trafficking hint", selectors: ["text:Sexual exploitation", "text:traffick", "text:trafficking"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Harassment", selectors: ["text:Harassment", "text:organized harassment"] },
        { label: "Organized harassment / doxxing", selectors: ["text:organized harassment", "text:doxx", "text:doxing"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Hate speech", selectors: ["text:Hate speech", "text:hate"] },
        { label: "Insults inciting others", selectors: ["text:insult", "text:incite", "text:dehumanize"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Spam", selectors: ["text:Spam", "text:phishing"] },
        { label: "Phishing / money request", selectors: ["text:phishing", "text:money request", "text:spam"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PostSet4
    {
      id: "PostSet4",
      name: "Post Set 4",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Nudity", selectors: ["text:Nudity"] },
        { label: "My images posted without consent", selectors: ["text:without consent", "text:my images", "text:posted without consent"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Harassment", selectors: ["text:Harassment"] },
        { label: "Stalking / repeated contact", selectors: ["text:stalking", "text:repeated contact"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Violent", selectors: ["text:Violent"] },
        { label: "Graphic injury / corpse images", selectors: ["text:corpse", "text:graphic", "text:graphic injury"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    },

    // PostSet5
    {
      id: "PostSet5",
      name: "Post Set 5",
      steps: [
        // Report 1
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Nudity", selectors: ["text:Nudity"] },
        { label: "Sexual content mixed with minors / exploitation", selectors: ["text:minor", "text:underage", "text:sexual", "text:exploitation"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 2
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Harassment", selectors: ["text:Harassment"] },
        { label: "Impersonation + harassment", selectors: ["text:impersonation", "text:impersonate", "text:harassment"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 3
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Violent/hate", selectors: ["text:Violent", "text:organised crime", "text:extremist"] },
        { label: "Organised crime promotion / extremist content", selectors: ["text:organised crime", "text:extremist", "text:terrorism"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] },

        // Report 4
        { label: "See Options", selectors: ["text:See Options"] },
        { label: "Report Post", selectors: ["text:Report post", "text:Report"] },
        { label: "Something about this post", selectors: ["text:Something about this post"] },
        { label: "Spam", selectors: ["text:Spam", "text:clickbait"] },
        { label: "Clickbait / malicious link", selectors: ["text:clickbait", "text:malicious link", "text:link to scam"] },
        { label: "Submit", selectors: ["text:Submit"] },
        { label: "Next", selectors: ["text:Next"] },
        { label: "Done", selectors: ["text:Done"] }
      ]
    }
  ]
};
