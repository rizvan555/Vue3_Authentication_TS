<template>
  <div class="auth-page">
    <div class="container page">
      <div class="row">
        <div class="flex flex-col gap-2 col-md-6 offset-md-3 col-xs-12">
          <h1 class="text-xs-center text-center text-2xl my-6 font-bold">
            SIGN UP
          </h1>
          <p class="text-xs-center">
            <router-link :to="{ name: 'signIn' }">
              Have an account?
            </router-link>
          </p>

          <form @submit.prevent="onSubmit" class="flex flex-col gap-3">
            <fieldset class="form-group">
              <input
                v-model="formData.username"
                class="form-control form-control-lg"
                :class="{ 'border-red-500': errors.username }"
                type="text"
                placeholder="Username"
                @input="clearError('username')"
              />
              <div v-if="errors.username" class="text-red-500">
                {{ errors.username }}
              </div>
            </fieldset>
            <fieldset class="form-group">
              <input
                v-model="formData.email"
                class="form-control form-control-lg"
                :class="{ 'border-red-500': errors.email }"
                type="text"
                placeholder="Email"
                autocomplete="email"
                @input="clearError('email')"
              />
              <div v-if="errors.email" class="text-red-500">
                {{ errors.email }}
              </div>
            </fieldset>
            <fieldset class="form-group">
              <input
                v-model="formData.password"
                class="form-control form-control-lg"
                :class="{ 'border-red-500': errors.password }"
                type="password"
                placeholder="Password"
                autocomplete="current-password"
                @input="clearError('password')"
              />
              <div v-if="errors.password" class="text-red-500">
                {{ errors.password }}
              </div>
            </fieldset>
            <button
              type="submit"
              class="btn btn-lg btn-primary pull-xs-right bg-blue-500"
              :disabled="isSubmitting"
            >
              Signup
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { setItem } from '../helper/persistanceStorage';
import router from '../router/index';
import * as Yup from 'yup';
import bcrypt from 'bcryptjs';
import axios from '../api/axios';
import type { Errors, FormData } from '@/types';

const formData = ref<FormData>({
  username: '',
  email: '',
  password: '',
});

const isSubmitting = ref(false);

const schema = Yup.object().shape({
  username: Yup.string()
    .min(3, 'Username must be at least 3 characters')
    .required('Username is required'),
  email: Yup.string().email('Invalid email').required('Email is required'),
  password: Yup.string()
    .min(6, 'Password must be at least 6 characters')
    .required('Password is required'),
});

const errors = ref<Errors>({});

const clearError = (field: keyof Errors) => {
  errors.value[field] = '';
};

const onSubmit = async (e: any) => {
  e.preventDefault();
  try {
    const config = {
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true,
    };
    isSubmitting.value = true;
    await schema.validate(formData.value, { abortEarly: false });
    // formData.value.password = await bcrypt.hash(formData.value.password, 10);

    const response = await axios.post('/api/users', formData.value, config);

    console.log('Server Response:', response.data);

    setItem('token', response.data.token);
    router.push({ name: 'signIn' });
  } catch (error: any) {
    if (error.name === 'ValidationError') {
      errors.value = error.inner.reduce((acc: Errors, err: any) => {
        acc[err.path] = err.message;
        return acc;
      }, {});
      isSubmitting.value = false;
    }
    console.error('Registration Error:', error);
  }
};
</script>
