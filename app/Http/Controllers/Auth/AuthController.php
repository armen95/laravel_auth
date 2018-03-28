<?php

namespace App\Http\Controllers\Auth;

use App\User;
use Validator;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Foundation\Auth\AuthenticatesAndRegistersUsers;
use Illuminate\Http\Request;
use Mail;
use Illuminate\Support\Facades\Input;

class AuthController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Registration & Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users, as well as the
    | authentication of existing users. By default, this controller uses
    | a simple trait to add these behaviors. Why don't you explore it?
    |
    */

    use AuthenticatesAndRegistersUsers, ThrottlesLogins;

    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware($this->guestMiddleware(), ['except' => 'logout']);
    }

    public function showLoginForm()
    {

        return view('auth.login');
    }

    public function login(Request $request)
    {
        $rules = array(
            'email'    => 'required|email',
            'password' => 'required'
        );

        $validator = Validator::make($request->all(), $rules);

        $remember_me = $request->has('remember') ? true : false; 
        if ($validator->fails()) {
            return redirect('login')
                ->withErrors($validator)
                ->withInput(Input::except('password'));
        } else {
            $userdata = array(
                'email'     => $request->get('email'),
                'password'  => $request->get('password')
            );
            if (auth()->attempt($userdata, $remember_me)) {
                return redirect($this->redirectTo);
            } else {        
                return redirect('login')->with('error','Invalid Credentials , Please try again.');
            }
        }

    }

    public function showRegistrationForm()
    {

        return view('auth.register');
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|unique:users|email',
            'password' => 'required|confirmed|min:6',
            'password_confirmation' => 'required'
        ]);

        if ($validator->fails()) {
            return redirect()->back()
                ->withErrors($validator)
                ->withInput();
        }
        else{
            $user = new User();
            $user->name = $request->get( 'name' );
            $user->email = $request->get( 'email' );
            $user->password = bcrypt( $request->get( 'password' ) );
            $user->email_token = base64_encode($request->get( 'email' ));
            $user->remember_token = $request->get( '_token' );
            $user->save();

            Mail::send('auth.emails.verify', ['user' => $user], function ($m) use ($user) {
                $m->from('admin@app.com', 'Auth Application');
                $m->to($user->email, $user->name)->subject('Verify Account');
            });

            return redirect()->back()->with('registered', 'Check your email to confirm account.');

        }

    }

    public function verify($token)
    {
        $user = User::where('email_token', $token)->first();
        if(count($user) > 0){
            $user->verified = 1;
            $user->email_token = '';
            if($user->save()){
                return redirect('login')->with('activated', 'Your Email is successfully verified.');
            }
        }
        else{
            return redirect('login')->with('verified', 'Your Email is already verified');
        }
    }

    public function logout()
    {
        auth()->logout();
        return redirect('login');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|min:6|confirmed',
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);
    }
}
