<button id="checkout-button">Pay with Stripe</button>

<script src="https://js.stripe.com/v3/"></script>
<script type="text/javascript">
  var stripe = Stripe('pk_test_your_publishable_key');  // Your public key here
  var checkoutButton = document.getElementById('checkout-button');

  checkoutButton.addEventListener('click', function () {
    fetch('/create-checkout-session', {  // You'll call your server-side to create a session
      method: 'POST'
    })
    .then(function (response) {
      return response.json();
    })
    .then(function (sessionId) {
      return stripe.redirectToCheckout({ sessionId: sessionId.id });
    })
    .then(function (result) {
      if (result.error) {
        alert(result.error.message);
      }
    })
    .catch(function (error) {
      console.error("Error:", error);
    });
  });
</script>
