const truthyValues = ['1', 'true', 'yes', 'on'];

export const paidPlansEnabled = truthyValues.includes(
  String(process.env.REACT_APP_PAID_PLANS_ENABLED || 'false').trim().toLowerCase()
);

export const publicFreeEdition = !paidPlansEnabled;