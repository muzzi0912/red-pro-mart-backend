<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use App\Models\Role;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Register a new user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        // Validation rules for registration
        $validator = Validator::make($request->all(), [
            'full_name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        // Return validation errors if validation fails
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        // Create a new user
        $user = new User([
            'full_name' => $request->full_name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);
        $user->save();

        // Assign the 'user' role to the user
        $user->roles()->attach(Role::where('name', 'user')->first());

        // Return success message
        return response()->json(['message' => 'User successfully registered'], 201);
    }

    /**
     * Log in the user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // Attempt to authenticate user
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
            // Get the authenticated user
            $user = Auth::user();
            // Generate a token for the user
            $token = $user->createToken('authToken')->plainTextToken;
            // Return the user data along with the token
            return response()->json(['user' => $user, 'token' => $token], 200);
        }

        // Return error message if authentication fails
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    /**
     * Log out the user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        // Revoke all tokens associated with the user
        $request->user()->tokens()->delete();

        // Return success message
        return response()->json(['message' => 'Logged out successfully'], 200);
    }
}
