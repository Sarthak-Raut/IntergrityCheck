package com.example.integritycheck

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import integritycheck.databinding.ActivityMainBinding
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.sampleText.text = stringFromJNI()

        binding.patchFunction.setOnClickListener {
            val response = patchFunction()
            val snackBar = when(response){
                1 -> Snackbar.make(binding.mainLayout, "Function Patched", Snackbar.LENGTH_LONG)
                0 -> Snackbar.make(binding.mainLayout, "Function Fixed", Snackbar.LENGTH_LONG)
                else -> Snackbar.make(binding.mainLayout, "Unknown Error", Snackbar.LENGTH_LONG)
            }
            snackBar.show()
        }

    }

    private val scope = CoroutineScope(Job() + Dispatchers.IO)
    private val scope2 = CoroutineScope(Job() + Dispatchers.IO)

    override fun onStart() {
        super.onStart()
        scope.launch {
            createThread();
        }

        scope2.launch {
            while (true){
                delay(1000)
                val string = stringFromJNI()
                runOnUiThread {
                    binding.sampleText.text = string
                }
            }
        }

    }

    private external fun stringFromJNI(): String
    private external fun createThread(): Int
    private external fun patchFunction(): Int

    companion object {
        init {
            System.loadLibrary("integritycheck")
        }
    }
}