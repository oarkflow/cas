package main

import (
	"fmt"

	"github.com/oarflow/cas/utils"
)

func main() {
	fmt.Println(utils.MatchResource("GET /users/123", "GET /users/:id"))                     // true
	fmt.Println(utils.MatchResource("POST /files/upload", "POST /files/*"))                  // true
	fmt.Println(utils.MatchResource("DELETE /orders/456/item", "DELETE /orders/:orderId/*")) // true
	fmt.Println(utils.MatchResource("ACTIONXYZ", "ACTION*"))                                 // true
	fmt.Println(utils.MatchResource("RES/ONE/TWO", "RES/:seg/THREE"))                        // false
	fmt.Println(utils.MatchResource("CREATE_USER", "CREATE_*"))                              // true
	fmt.Println(utils.MatchResource("UPDATE_USER_PROFILE", "UPDATE_USER_*"))                 // true
	fmt.Println(utils.MatchResource("DELETE_ITEM", "DELETE/:type"))                          // false
}
