package tech.skot.libraries.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Before
import org.junit.Test
import tech.skot.core.components.inputs.SKButtonViewProxy
import tech.skot.core.di.BaseInjector
import tech.skot.core.di.injector
import tech.skot.core.di.module
import tech.skot.view.tests.SKTestScreenViewProxy
import tech.skot.view.tests.SKTestView
import tech.skot.view.tests.testScreen

class SecurityActionsImplTestView: SKTestView() {


   @Test
   fun testSecurity() {


       val screen = SKTestScreenViewProxy(listOf())
       testScreen(screen) { scenario ->
           scenario.onActivity {  activity ->
               val actions = SecurityActionsImpl(activity, null, activity.window.decorView)

               screen.box.items = listOf(
                   SKButtonViewProxy(
                       labelInitial = "check Availability",
                       onTapInitial = {
                           actions.getBioAuthentAvailability {
                               toast("Availability :$it")()
                           }
                       }
                   )
               )

           }
       }

   }

}