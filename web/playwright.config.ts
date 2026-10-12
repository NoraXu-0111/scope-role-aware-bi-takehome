import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',workers:1,retries:0,reporter:'list',use:{baseURL:'http://127.0.0.1:8765',channel:'chrome',headless:true,viewport:{width:1440,height:1000}},outputDir:'../.runtime/browser-tests'});
