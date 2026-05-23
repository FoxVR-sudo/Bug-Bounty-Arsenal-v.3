const truthyValues = ['1', 'true', 'yes', 'on'];

export const accessControlsEnabled = truthyValues.includes(
  String(process.env.REACT_APP_ACCESS_CONTROLS_ENABLED || 'false').trim().toLowerCase()
);

export const openSourceRelease = !accessControlsEnabled;