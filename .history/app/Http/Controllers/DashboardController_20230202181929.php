<?php

namespace App\Http\Controllers;

use App\Services\SallaAuthService;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Salla\OAuth2\Client\Provider\Salla;

class DashboardController extends Controller
{
    /**
     * @var SallaAuthService
     */
    private $salla;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct(SallaAuthService $salla)
    {
        $this->middleware('auth');
        $this->salla = $salla;
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable|\Illuminate\Http\RedirectResponse
     * @throws IdentityProviderException
     */
    public function __invoke()
    {
        $products = [];
        $store = null;

        $provider = new Salla([
            'clientId'     => '028d5ed393850a56ea251d69822986fa', // The client ID assigned to you by Salla
            'clientSecret' => 'd5d0e1ab321a825ffefee42675edcca1', // The client password assigned to you by Salla
            'redirectUri'  => 'http://127.0.0.1:8000/callback_url', // the url for current page in your service
        ]);

        /**
         * In case the current callback url doesn't have an authorization_code
         * Let's redirect the merchant to installation/authorization app workflow
         */
        if (empty($_GET['code'])) {
            $authUrl = $provider->getAuthorizationUrl([
                'scope' => 'offline_access',
                //Important: If you want to generate the refresh token, set this value as offline_access
            ]);

            header('Location: ' . $authUrl);
            exit;
        }

        /**
         * The merchant complete the installation/authorization app workflow
         * And the callback url have an authorization_code as parameter
         * Let's exchange the authorization_code with access token
         */
        try {
            $token = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);

            //
            // ## Access Token
            //
            // You should store the access token
            // which may use in authenticated requests against the Salla's API
            echo 'Access Token: ' . $token->getToken() . "<br>";

            //
            // ## Refresh Token
            //
            // You should store the refresh token somewhere in your system because the access token expired after 14 days,
            // so you can use the refresh token after that to generate a new access token without asking any access from the merchant
            //
            // $token = $provider->getAccessToken(new RefreshToken(), ['refresh_token' => $token->getRefreshToken()]);
            //
            echo 'Refresh Token: ' . $token->getRefreshToken() . "<br>";

            //
            // ## Expire date
            //
            // This helps you to know when the access token will be expired
            // so before that date, you should generate a new access token using the refresh token
            echo 'Expire Date : ' . $token->getExpires() . "<br>";

            //
            // ## Merchant Details
            //
            // Using the access token, we may look up details about the merchant.
            // --- Same request in Curl ---
            // curl --request GET --url 'https://accounts.salla.sa/oauth2/user/info' --header 'Authorization: Bearer <access-token>'

            /** @var \Salla\OAuth2\Client\Provider\SallaUser $user */
            $user = $provider->getResourceOwner($token);

            /**
             *  {
             *    "id": 1771165749,
             *    "name": "Test User",
             *    "email": "testuser@email.partners",
             *    "mobile": "+966500000000",
             *    "role": "user",
             *    "created_at": "2021-12-31 11:36:57",
             *    "merchant": {
             *      "id": 1803665367,
             *      "username": "dev-j8gtzhp59w3irgsw",
             *      "name": "dev-j8gtzhp59w3irgsw",
             *      "avatar": "https://i.ibb.co/jyqRQfQ/avatar-male.webp",
             *      "store_location": "26.989000873354787,49. 62477639657287",
             *      "plan": "special",
             *      "status": "active",
             *      "domain": "https://salla.sa/YOUR-DOMAIN-NAME",
             *      "created_at": "2021-12-31 11:36:57"
             *    }
             *  }
             */
            var_export($user->toArray());

            echo 'User ID: ' . $user->getId() . "<br>";
            echo 'User Name: ' . $user->getName() . "<br>";
            echo 'Store ID: ' . $user->getStoreID() . "<br>";
            echo 'Store Name: ' . $user->getStoreName() . "<br>";


            //
            // 🥳
            //
            // You can now save the access token and refresh the token in your database
            // with the merchant details and redirect him again to Salla dashboard (https://s.salla.sa/apps)


            //
            // ## Access to authenticated APIs for the merchant
            //
            // You can also use the same package to call any authenticated APIs for the merchant
            // Using the access token, information can be obtained from a list of endpoints.
            //
            // --- Same request in Curl ---
            // curl --request GET --url 'https://api.salla.dev/admin/v2/orders' --header 'Authorization: Bearer <access-token>'
            $response = $provider->fetchResource(
                'GET',
                'https://api.salla.dev/admin/v2/orders',
                $token->getToken()
            );

            var_export($response);
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            // Failed to get the access token or merchant details.
            // show an error message to the merchant with good UI
            exit($e->getMessage());
        }

        if (auth()->user()->token) {
            // set the access token to our service
            // you can load the user profile from your database in your app
            $this->salla->forUser(auth()->user());

            // you need always to check the token before made a request
            // If the token expired, lets request a new one and save it to the database
            try {
                $this->salla->getNewAccessToken();
            } catch (IdentityProviderException $exception) {
                // in case the token access token & refresh token is expired
                // lets redirect the user again to Salla authorization service to get a new token
                return redirect()->route('oauth.redirect');
            }

            // let's get the store details to show it
            $store = $this->salla->getStoreDetail();

            // let's get the product of store via salla service
            $products = $this->salla->request('GET', 'https://api.salla.dev/admin/v2/products')['data'];

            /**
             * Or you can use Http client of laravel to get the products
             */
            //$response = Http::asJson()->withToken($this->salla->getToken()->access_token)
            //    ->get('https://api.salla.dev/admin/v2/products');

            //if ($response->status() === 200) {
            //    $products = $response->json()['data'];
            //}
        }

        return view('dashboard', [
            // get the first 8 products from the response
            'products' => array_slice($products, 0, min(8, count($products))),
            'store'    => $store
        ]);
    }
}
