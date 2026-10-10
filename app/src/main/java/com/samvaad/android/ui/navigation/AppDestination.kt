package com.samvaad.android.ui.navigation

import android.os.Parcel
import android.os.Parcelable
import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

/**
 * Authenticated destinations (Slice B: Navigation 3 foundation).
 *
 * Type-safe keys: the conversation ID is the ChatDetail route identity.
 * Message objects never travel through navigation; detail content loads
 * from the existing durable store owned by the messaging graph.
 *
 * Parcelable is hand-written (no parcelize plugin) so this slice adds
 * no Kotlin compiler plugins.
 */
sealed interface AppDestination : NavKey, Parcelable {
    @Serializable
    data object Chats : AppDestination {
        override fun describeContents(): Int = 0

        override fun writeToParcel(dest: Parcel, flags: Int) = Unit

        @JvmField
        val CREATOR: Parcelable.Creator<Chats> =
            object : Parcelable.Creator<Chats> {
                override fun createFromParcel(parcel: Parcel): Chats = Chats

                override fun newArray(size: Int): Array<Chats?> = arrayOfNulls(size)
            }
    }

    @Serializable
    data object Friends : AppDestination {
        override fun describeContents(): Int = 0

        override fun writeToParcel(dest: Parcel, flags: Int) = Unit

        @JvmField
        val CREATOR: Parcelable.Creator<Friends> =
            object : Parcelable.Creator<Friends> {
                override fun createFromParcel(parcel: Parcel): Friends = Friends

                override fun newArray(size: Int): Array<Friends?> = arrayOfNulls(size)
            }
    }

    @Serializable
    data object Settings : AppDestination {
        override fun describeContents(): Int = 0

        override fun writeToParcel(dest: Parcel, flags: Int) = Unit

        @JvmField
        val CREATOR: Parcelable.Creator<Settings> =
            object : Parcelable.Creator<Settings> {
                override fun createFromParcel(parcel: Parcel): Settings = Settings

                override fun newArray(size: Int): Array<Settings?> = arrayOfNulls(size)
            }
    }

    @Serializable
    data class ChatDetail(val conversationId: String) : AppDestination {
        override fun describeContents(): Int = 0

        override fun writeToParcel(dest: Parcel, flags: Int) {
            dest.writeString(conversationId)
        }

        companion object {
            @JvmField
            val CREATOR: Parcelable.Creator<ChatDetail> =
                object : Parcelable.Creator<ChatDetail> {
                    override fun createFromParcel(parcel: Parcel): ChatDetail =
                        ChatDetail(parcel.readString().orEmpty())

                    override fun newArray(size: Int): Array<ChatDetail?> =
                        arrayOfNulls(size)
                }
        }
    }
}

/**
 * Which slice of the authenticated content is visible.
 *
 * [HomeSection.Full] preserves the pre-Nav3 HomeScreen rendering (used by existing
 * tests and as the fallback). Sectioned modes render one slice each;
 * navigation (not this enum) owns where the user is.
 */
enum class HomeSection {
    Full,
    Chats,
    Friends,
    Settings,
    Detail,
}
