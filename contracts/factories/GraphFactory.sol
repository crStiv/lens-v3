// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccessControl} from "./../primitives/access-control/IAccessControl.sol";
import {Graph} from "./../primitives/graph/Graph.sol";
import {OwnerOnlyAccessControl} from "./../primitives/access-control/OwnerOnlyAccessControl.sol";
import {RuleConfiguration} from "./../types/Types.sol";

contract GraphFactory {
    event Lens_GraphFactory_Deployment(address indexed graph);

    IAccessControl internal immutable _factoryOwnedAccessControl;

    constructor() {
        _factoryOwnedAccessControl = new OwnerOnlyAccessControl({owner: address(this)});
    }

    function deploy(string memory metadataURI, IAccessControl accessControl, RuleConfiguration[] calldata rules)
        external
        returns (address)
    {
        Graph graph = new Graph(metadataURI, _factoryOwnedAccessControl);
        graph.addGraphRules(rules);
        graph.setAccessControl(accessControl);
        emit Lens_GraphFactory_Deployment(address(graph));
        return address(graph);
    }
}
