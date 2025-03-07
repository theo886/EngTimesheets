// Sample projects data
const projects = [
  { id: 1, name: "Website Redesign", code: "WEB-001" },
  { id: 2, name: "Mobile App Development", code: "APP-002" },
  { id: 3, name: "Internal Dashboard", code: "DASH-003" },
  { id: 4, name: "Client Onboarding System", code: "CL-004" },
  { id: 5, name: "Infrastructure Upgrade", code: "INF-005" },
  { id: 6, name: "Data Migration", code: "DM-006" },
  { id: 7, name: "Security Audit", code: "SEC-007" },
  { id: 8, name: "Training & Documentation", code: "TD-008" }
];

// Function to generate and load fake data for testing
function loadFakeDataForTesting(currentWeek, formatWeekRange) {
  const fakeProjectIds = ["1", "2", "3", "4", "5"];
  const projectNames = {
    "1": "Website Redesign",
    "2": "Mobile App Development",
    "3": "Internal Dashboard",
    "4": "Client Onboarding System",
    "5": "Infrastructure Upgrade"
  };
  
  // Generate dates for 5 consecutive weeks starting from 5 weeks ago
  const startDate = new Date(currentWeek);
  startDate.setDate(startDate.getDate() - (7 * 5)); // Start 5 weeks ago
  
  const weekDates = [];
  for (let i = 0; i < 5; i++) {
    const weekStart = new Date(startDate);
    weekStart.setDate(weekStart.getDate() + (i * 7));
    weekDates.push(weekStart);
  }
  
  // Story arcs for each project over 5 weeks
  const projectStories = {
    // Website Redesign: starts high, gradually decreases
    "1": [35, 30, 25, 20, 15],
    
    // Mobile App: starts low, increases, then plateaus
    "2": [15, 25, 35, 35, 30],
    
    // Internal Dashboard: steady in the middle
    "3": [20, 20, 15, 20, 20],
    
    // Client Onboarding: not present initially, increases later
    "4": [0, 5, 10, 15, 20],
    
    // Infrastructure: starts high, decreases, then disappears
    "5": [30, 20, 15, 10, 0]
  };
  
  const previousSubmissions = {};
  
  // Generate entries for each week
  weekDates.forEach((date, weekIndex) => {
    const weekKey = formatWeekRange(date);
    const weekEntries = [];
    
    // Create entries for each project for this week
    fakeProjectIds.forEach(projectId => {
      const percentage = projectStories[projectId][weekIndex];
      
      // Only add projects with non-zero allocation
      if (percentage > 0) {
        weekEntries.push({
          id: Date.now() + Math.random(), // Generate unique ID
          projectId: projectId,
          projectName: projectNames[projectId],
          percentage: percentage.toString()
        });
      }
    });
    
    // Ensure percentages add up to 100%
    const totalPercentage = weekEntries.reduce((sum, entry) => sum + parseInt(entry.percentage), 0);
    if (totalPercentage !== 100 && weekEntries.length > 0) {
      // Add or subtract from the last entry to make total 100%
      const lastEntry = weekEntries[weekEntries.length - 1];
      const adjustment = 100 - totalPercentage;
      lastEntry.percentage = (parseInt(lastEntry.percentage) + adjustment).toString();
    }
    
    // Store in previousSubmissions
    previousSubmissions[weekKey] = weekEntries;
  });
  
  console.log("Fake data loaded for the following weeks:", Object.keys(previousSubmissions));
  return previousSubmissions;
}

// Expose variables and functions globally
window.projects = projects;
window.loadFakeDataForTesting = loadFakeDataForTesting; 