import React, { useState } from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement, useStripe, useElements } from '@stripe/react-stripe-js';

let stripePromise;

const getStripePromise = () => {
  const key = process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY;
  const isValidKey = typeof key === 'string' && key.trim().startsWith('pk_');
  if (!isValidKey) return null;
  if (!stripePromise) {
    stripePromise = loadStripe(key.trim());
  }
  return stripePromise;
};

// Payment form component (inside Elements provider)
const PaymentForm = ({ clientSecret, onSuccess, onError }) => {
  const stripe = useStripe();
  const elements = useElements();
  const [isProcessing, setIsProcessing] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!stripe || !elements) {
      return;
    }

    setIsProcessing(true);
    setErrorMessage('');

    try {
      const { error } = await stripe.confirmPayment({
        elements,
        confirmParams: {
          return_url: `${window.location.origin}/subscription?payment=success`,
        },
        redirect: 'if_required', // Don't redirect if payment succeeds
      });

      if (error) {
        setErrorMessage(error.message);
        setIsProcessing(false);
        if (onError) onError(error);
      } else {
        // Payment succeeded
        setIsProcessing(false);
        if (onSuccess) onSuccess();
      }
    } catch (err) {
      setErrorMessage('An unexpected error occurred.');
      setIsProcessing(false);
      if (onError) onError(err);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="payment-form">
      <PaymentElement />
      
      {errorMessage && (
        <div className="alert alert-danger mt-3">
          {errorMessage}
        </div>
      )}
      
      <button
        type="submit"
        disabled={!stripe || isProcessing}
        className="btn btn-primary btn-lg w-100 mt-4"
      >
        {isProcessing ? (
          <>
            <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
            Processing...
          </>
        ) : (
          `Pay & Activate Enterprise Plan`
        )}
      </button>
    </form>
  );
};

// Main wrapper component
const EnterprisePaymentForm = ({ clientSecret, onSuccess, onError }) => {
  const stripe = getStripePromise();

  if (!stripe) {
    return (
      <div className="stripe-payment-wrapper">
        <div className="alert alert-warning">
          Payments are temporarily unavailable (Stripe is not configured).
        </div>
      </div>
    );
  }

  const options = {
    clientSecret,
    appearance: {
      theme: 'stripe',
      variables: {
        colorPrimary: '#0052ff',
      },
    },
  };

  return (
    <div className="stripe-payment-wrapper">
      <Elements stripe={stripe} options={options}>
        <PaymentForm 
          clientSecret={clientSecret}
          onSuccess={onSuccess}
          onError={onError}
        />
      </Elements>
    </div>
  );
};

export default EnterprisePaymentForm;
