<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Hash;
use App\Models\User;
use Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8'],
            'device_name' => ['required']
        ]);

        $data['password'] = Hash::make($request->password);
        $data['is_admin'] = $request->is_admin ?? false;

        $user = User::create($data);

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'The provided cerdentials are incorrect.',
            ], 422);
        }

        $accessToken = Auth::user()->createToken($request->device_name)->plainTextToken;

        return response()->json([
            'message' => 'success',
            'data' => $user,
            'meta' => [
                'token' => $accessToken
            ]
        ], 201);
        
    }

    public function login(Request $request) {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
            'device_name' => 'required',
        ]);
     
        $user = User::where('email', $request->email)->first();
     
        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }
     
        $accessToken = $user->createToken($request->device_name)->plainTextToken;

        return response()->json([
            'message' => 'success',
            'data' => $user,
            'meta' => [
                'token' => $accessToken
            ]
        ], 201);

        
    }

    public function logout(Request $request){
        $request->user()->tokens()->delete();
        return response()->json([
            'message' => 'success',
          
        ], 200);

    }

}
